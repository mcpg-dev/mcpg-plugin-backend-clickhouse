//! ClickHouse columnar-OLAP backend binding plugin for mcpg.
//!
//! Implements [`ClickHouseBackendPlugin`] — `BackendPlugin` for
//! `kind: "clickhouse"`. Runs an operator-fixed analytical statement whose `?`
//! placeholders are bound from CEL expressions evaluated against the tool
//! arguments (bound + escaped as ClickHouse SQL literals by the driver, never
//! interpolated — injection-safe), against a ClickHouse server over its HTTP
//! interface. A read-only keyword guard plus a server-side `readonly=1` setting
//! fence the statement. Structurally mirrors the duckdb/snowflake backends;
//! ClickHouse-specific machinery lives in [`engine`] + [`params`] + [`envelope`]
//! + [`surface`].
//!
//! The `clickhouse::Client` is built once at `register_profile` — that is
//! I/O-free (no socket is opened until the first query), so registration stays
//! offline-testable. TLS always verifies the server certificate; a binding that
//! sets `tls.verify_peer = false` is rejected at register (there is no
//! certificate-verification opt-out — configure a trusted CA instead).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use clickhouse::Client;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    ResourcePage, firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mod cdylib;
mod engine;
mod envelope;
mod params;
mod surface;
mod types;
pub mod watch;

use engine::{
    QueryOutcome, build_client, build_list_columns_query, build_list_tables_query,
    enforce_read_only, run_query_with_settings,
};
use envelope::{build_result_envelope, classify_error};
use params::{ChBind, CompiledParam, compile_params, evaluate_params, json_to_ch_bind};
pub use types::{
    ClickHouseBackendSpec, ClickHouseOperation, CompletionConfig as ClickHouseCompletionConfig,
    ListQueryConfig, ListQueryMode, validate_completion, validate_list_query,
};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

/// ClickHouse default database name (used as the envelope `request.database`
/// label when the operator omits an explicit `database`).
const DEFAULT_DATABASE: &str = "default";

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.clickhouse.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.clickhouse.request_failed"),
        "clickhouse_error" => Some("dev.mcpg.backend.clickhouse.query_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.clickhouse.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.clickhouse".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("ClickHouse plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

/// Reject a bare `cred://` URI in an operator-fixed string. Secrets reach the
/// server through `${cred://…}` resolved at config load (the auth password); a
/// bare `cred://` left in a statement would be sent to ClickHouse verbatim,
/// which is always an operator mistake.
fn reject_bare_cred(field: &str, value: &str) -> Result<(), String> {
    if value.contains("cred://") {
        return Err(format!(
            "{field} must not contain a bare cred:// URI — use ${{cred://…}} (resolved at config load)"
        ));
    }
    Ok(())
}

/// Per-binding catalog-introspection filter config for the `list_tables` /
/// `list_columns` operations: an operator-pinned static value plus an optional
/// tool-argument name for the database / table filter. Resolved per call; the
/// per-call argument (when configured AND present as a JSON string) overrides the
/// static value. Every resolved filter is passed as a BOUND query parameter —
/// never interpolated into SQL — so caller input can only narrow the metadata.
#[derive(Debug, Default, Clone)]
struct CatalogFilterConfig {
    database: Option<String>,
    database_arg: Option<String>,
    table: Option<String>,
    table_arg: Option<String>,
}

impl CatalogFilterConfig {
    /// Resolve the (database, table) filters for one call. For each, the per-call
    /// argument (when configured and present as a JSON string) wins over the
    /// static value; otherwise the static value (or None = no filter) is used.
    fn resolve(&self, arguments: &Value) -> (Option<String>, Option<String>) {
        (
            resolve_one(
                self.database.as_deref(),
                self.database_arg.as_deref(),
                arguments,
            ),
            resolve_one(self.table.as_deref(), self.table_arg.as_deref(), arguments),
        )
    }

    /// The distinct tool-argument names this config reads from call arguments —
    /// surfaced as the catalog op's `input_schema` properties.
    fn argument_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for arg in [&self.database_arg, &self.table_arg].into_iter().flatten() {
            if !names.contains(arg) {
                names.push(arg.clone());
            }
        }
        names
    }
}

/// Resolve a single catalog filter: a caller-supplied string argument (when the
/// `arg_name` is configured and the argument is a JSON string) overrides the
/// operator-pinned `static_value`; absent both, `None` = match all.
fn resolve_one(
    static_value: Option<&str>,
    arg_name: Option<&str>,
    arguments: &Value,
) -> Option<String> {
    if let Some(name) = arg_name
        && let Some(v) = arguments.get(name).and_then(Value::as_str)
    {
        return Some(v.to_owned());
    }
    static_value.map(str::to_owned)
}

// ------------------------------------------------------------------ plugin

/// Per-binding ClickHouse runtime — the cheap-cloneable HTTP client plus the
/// compiled statement and query bounds. The `Client` is I/O-free configuration
/// (built at register; the socket opens on first query) and internally
/// connection-pooled, so each call clones it cheaply. Statement / params /
/// completions sit behind `Arc` so the whole profile is cheap to clone per call.
#[derive(Clone)]
struct ClickHouseProfile {
    client: Client,
    /// Database label for the envelope `request.database` (the `Client` carries
    /// the real connection database; this is purely for the response shape).
    database: String,
    operation: ClickHouseOperation,
    read_only: bool,
    statement: String,
    compiled_params: Arc<[CompiledParam]>,
    /// Catalog-introspection filter config (static + per-call argument names).
    /// Only consulted for the `list_tables` / `list_columns` operations.
    catalog_filters: Arc<CatalogFilterConfig>,
    max_rows: usize,
    timeout: Duration,
    /// Operator-fixed per-query ClickHouse settings (applied via `.with_option`).
    settings: Arc<[(String, String)]>,
    surface: surface::Surface,
    surface_uri: Option<String>,
    list_query: Option<ListQueryConfig>,
    /// Per-`{id}` single-row read statement for a `resource_templates[]`
    /// binding. Bound from the same `compiled_params` as `statement`; when None
    /// the resource-read branch falls back to `statement`.
    read_query: Option<String>,
    variable_completions: Arc<BTreeMap<String, ClickHouseCompletionConfig>>,
}

/// `BackendPlugin` implementation for `kind: "clickhouse"`.
pub struct ClickHouseBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, ClickHouseProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for ClickHouseBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ClickHouseBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.clickhouse",
                name: "ClickHouse Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Per-call observability triad (latency + counter + optional audit).
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_clickhouse_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_clickhouse_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("clickhouse-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("clickhouse-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::clickhouse::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }

    /// Build an error envelope (param-eval failures), emit the triad, and return
    /// it as a normal payload — matching the duckdb/snowflake backends.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &ClickHouseProfile,
        backend_name: &str,
        tool_name: &str,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = classify_error(message);
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            &profile.database,
            None,
            None,
            false,
            started.elapsed().as_millis(),
            Some(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    /// Run a statement for `profile`: bind the scalars, fetch `JSONEachRow`
    /// bytes, and marshal capped JSON rows. The server-side `max_execution_time`
    /// budget AND the outer tokio timeout both bound the call.
    async fn run_query(
        &self,
        profile: &ClickHouseProfile,
        statement: &str,
        bound: Vec<ChBind>,
        max_rows: usize,
    ) -> Result<QueryOutcome, String> {
        // Catalog ops are inherently read-only (a SELECT over `system.*`); the
        // server-side `readonly=1` is forced on regardless of the binding flag so
        // the introspection path can never mutate. Operator settings still apply.
        let read_only = profile.read_only || profile.operation.is_catalog();
        let fut = run_query_with_settings(
            &profile.client,
            statement,
            bound,
            max_rows,
            read_only,
            profile.timeout,
            &profile.settings,
        );
        match tokio::time::timeout(profile.timeout, fut).await {
            Ok(inner) => inner,
            Err(_) => Err("ClickHouse call timed out".to_owned()),
        }
    }
}

impl std::fmt::Debug for ClickHouseBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClickHouseBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for ClickHouseBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "clickhouse"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: ClickHouseBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("ClickHouse binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.url.trim().is_empty() {
            return Err(invalid("url must not be empty".into()));
        }
        // The `statement` is required only for `operation: query`; the catalog
        // operations build their own bound SELECT over `system.*` and ignore it.
        match parsed.operation {
            ClickHouseOperation::Query => {
                // A resource_template binding may supply only `read_query` (the
                // per-`{id}` single-row read) and omit `statement`; otherwise the
                // operator-fixed `statement` is required.
                if parsed.statement.trim().is_empty()
                    && parsed
                        .read_query
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err(invalid(
                        "statement must not be empty (or set `read_query` for a resource_template read binding)".into(),
                    ));
                }
            }
            ClickHouseOperation::ListColumns => {
                // `system.columns` needs a table to scope to (a static
                // `catalog_table` or a per-call `catalog_table_arg`); without
                // either it would list every column of every table.
                if parsed
                    .catalog_table
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                    && parsed
                        .catalog_table_arg
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err(invalid(
                        "operation: list_columns requires a `catalog_table` filter or a `catalog_table_arg` (the table whose columns to list)".into(),
                    ));
                }
            }
            ClickHouseOperation::ListTables => {}
        }
        if parsed.query.max_execution_time_ms == 0 {
            return Err(invalid(
                "query.max_execution_time_ms must be greater than 0".into(),
            ));
        }
        if parsed.query.max_result_rows == 0 {
            return Err(invalid(
                "query.max_result_rows must be greater than 0".into(),
            ));
        }
        // Certificate verification has no opt-out — an insecure no-verify client
        // is not built. Reject the disabling flag at register with a clear hint.
        if !parsed.tls.verify_peer {
            return Err(invalid(
                "clickhouse tls.verify_peer=false is not supported; configure a trusted CA instead"
                    .into(),
            ));
        }
        reject_bare_cred("url", &parsed.url).map_err(invalid)?;
        reject_bare_cred("statement", &parsed.statement).map_err(invalid)?;

        // Read-only guard applies to the `query` operation only: the catalog
        // operations run a SELECT over `system.*`, which never mutates, so they
        // skip the keyword guard (and the read-only CEL `params` entirely).
        // The guard runs on a present `statement`; a resource_template read
        // binding may omit it (the per-`{id}` read lives in `read_query`, guarded
        // below).
        if parsed.operation == ClickHouseOperation::Query
            && parsed.query.read_only
            && !parsed.statement.trim().is_empty()
        {
            enforce_read_only(&parsed.statement).map_err(invalid)?;
        }

        // Surface coherence: `uri` is only meaningful on the resource surface; a
        // static `uri` on a tool/prompt binding is a config mistake worth a
        // fail-closed rejection rather than a silent no-op.
        if parsed.uri.is_some() && parsed.surface != surface::Surface::Resource {
            return Err(invalid(format!(
                "`uri` is only valid with `surface: resource` (this binding is `surface: {}`)",
                parsed.surface.as_str()
            )));
        }
        if let Some(u) = &parsed.uri
            && u.trim().is_empty()
        {
            return Err(invalid("`uri` must not be empty".into()));
        }

        // `read_query` is the per-`{id}` single-row read for a resource_template
        // binding; like `statement` it is operator-fixed, must be read-only under
        // the guard, and must not carry a bare cred://. It only makes sense on the
        // resource surface — fail-closed elsewhere so a misplaced field is never a
        // silent no-op.
        if let Some(rq) = &parsed.read_query {
            if rq.trim().is_empty() {
                return Err(invalid("`read_query` must not be empty".into()));
            }
            if parsed.surface != surface::Surface::Resource {
                return Err(invalid(format!(
                    "`read_query` is only valid with `surface: resource` (this binding is `surface: {}`)",
                    parsed.surface.as_str()
                )));
            }
            reject_bare_cred("read_query", rq).map_err(invalid)?;
            if parsed.query.read_only {
                enforce_read_only(rq).map_err(invalid)?;
            }
        }

        // Listing + completion are operator-fixed read surfaces; fail-closed at
        // register so a misconfigured `list_query` / `variable_completions`
        // never reaches a `resources/list` or `completion/complete` call.
        if let Some(lq) = &parsed.list_query {
            validate_list_query(lq).map_err(invalid)?;
            reject_bare_cred("list_query.sql", &lq.sql).map_err(invalid)?;
            if parsed.query.read_only {
                enforce_read_only(&lq.sql).map_err(invalid)?;
            }
        }
        for (name, cc) in &parsed.variable_completions {
            validate_completion(name, cc).map_err(invalid)?;
            reject_bare_cred(&format!("variable_completions.{name}.sql"), &cc.sql)
                .map_err(invalid)?;
            if parsed.query.read_only {
                enforce_read_only(&cc.sql).map_err(invalid)?;
            }
        }

        let compiled_params: Arc<[CompiledParam]> =
            compile_params(&parsed.params).map_err(invalid)?.into();

        // Build the I/O-free verifying client (no socket opened here, so register
        // stays offline). The database label below is purely for the envelope.
        let client = build_client(
            &parsed.url,
            parsed.database.as_deref(),
            parsed.auth.username.as_deref(),
            parsed.auth.password.as_deref(),
        );
        let database = parsed
            .database
            .clone()
            .unwrap_or_else(|| DEFAULT_DATABASE.to_owned());

        debug!(
            backend = %backend_name,
            url = %parsed.url,
            database = %database,
            read_only = parsed.query.read_only,
            params = compiled_params.len(),
            "registered ClickHouse binding profile"
        );

        let settings: Arc<[(String, String)]> = parsed
            .query
            .settings
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            ClickHouseProfile {
                client,
                database,
                operation: parsed.operation,
                read_only: parsed.query.read_only,
                statement: parsed.statement,
                compiled_params,
                catalog_filters: Arc::new(CatalogFilterConfig {
                    database: parsed.catalog_database,
                    database_arg: parsed.catalog_database_arg,
                    table: parsed.catalog_table,
                    table_arg: parsed.catalog_table_arg,
                }),
                max_rows: parsed.query.max_result_rows,
                timeout: Duration::from_millis(parsed.query.max_execution_time_ms),
                settings,
                surface: parsed.surface,
                surface_uri: parsed.uri,
                list_query: parsed.list_query,
                read_query: parsed.read_query,
                variable_completions: Arc::new(parsed.variable_completions),
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "clickhouse_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    let err = BackendError::InvalidSpec {
                        message: format!("ClickHouse plugin payload is not valid JSON: {e}"),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "invalid_spec",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        // Catalog-introspection ops bypass CEL params entirely: they resolve the
        // (optionally caller-supplied) database / table filters and run a bound
        // SELECT over `system.tables` / `system.columns`. The filters are BOUND
        // parameters — never interpolated — so caller input can only narrow the
        // metadata.
        let result: Result<QueryOutcome, String> = if profile.operation.is_catalog() {
            let (db_filter, tbl_filter) = profile.catalog_filters.resolve(&arguments);
            let catalog = match profile.operation {
                ClickHouseOperation::ListTables => {
                    build_list_tables_query(db_filter.as_deref(), profile.max_rows)
                }
                ClickHouseOperation::ListColumns => build_list_columns_query(
                    db_filter.as_deref(),
                    tbl_filter.as_deref(),
                    profile.max_rows,
                ),
                ClickHouseOperation::Query => unreachable!("is_catalog excludes Query"),
            };
            self.run_query(&profile, &catalog.sql, catalog.binds, profile.max_rows)
                .await
        } else {
            // Evaluate the CEL parameter expressions, then lower each to a scalar
            // ClickHouse bind (rejecting arrays/objects) — all connection-free.
            let bound = match evaluate_params(&profile.compiled_params, &arguments) {
                Ok(values) => {
                    let mut binds = Vec::with_capacity(values.len());
                    let mut err: Option<String> = None;
                    for v in values {
                        match json_to_ch_bind(v) {
                            Ok(b) => binds.push(b),
                            Err(e) => {
                                err = Some(format!("binding params: {e}"));
                                break;
                            }
                        }
                    }
                    if let Some(message) = err {
                        return self
                            .finish_error(
                                &profile,
                                backend_name,
                                &tool_name,
                                &message,
                                "invalid_spec",
                                identity.as_ref(),
                                &request_id,
                                started,
                                host_span,
                            )
                            .await;
                    }
                    binds
                }
                Err(e) => {
                    return self
                        .finish_error(
                            &profile,
                            backend_name,
                            &tool_name,
                            &format!("evaluating params: {e}"),
                            "invalid_spec",
                            identity.as_ref(),
                            &request_id,
                            started,
                            host_span,
                        )
                        .await;
                }
            };

            // On the resource surface a per-`{id}` `read_query` (when configured)
            // is the single-row read for a `resource_templates[]` binding; it
            // binds the same `params` (the gateway-extracted template vars reach
            // it as `arguments.<var>`). Every other surface — and a resource
            // binding without `read_query` — runs the operator-fixed `statement`.
            let effective_statement = match (profile.surface, profile.read_query.as_deref()) {
                (surface::Surface::Resource, Some(rq)) => rq,
                _ => &profile.statement,
            };
            self.run_query(&profile, effective_statement, bound, profile.max_rows)
                .await
        };

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                Ok(outcome) => {
                    // On the resource/prompt surfaces the gateway decoder
                    // requires a surface-shaped body; the tool surface keeps the
                    // historical envelope. A resource read with no resolvable URI
                    // falls back to the tool error envelope (carries
                    // `downstreamError` → gateway `is_error`) so the decoder sees
                    // a clean error rather than an invalid `{contents}`.
                    match profile.surface {
                        surface::Surface::Tool => (
                            build_result_envelope(
                                &tool_name,
                                backend_name,
                                &profile.database,
                                Some(&outcome.rows),
                                Some(outcome.row_count),
                                outcome.truncated,
                                started.elapsed().as_millis(),
                                None,
                                None,
                            ),
                            "ok",
                            None,
                        ),
                        surface::Surface::Resource => {
                            match surface::resolve_resource_uri(
                                profile.surface_uri.as_deref(),
                                &arguments,
                            ) {
                                Some(uri) => (
                                    surface::resource_contents_body(uri, &outcome.rows),
                                    "ok",
                                    None,
                                ),
                                None => {
                                    let message = "resource surface requires a `uri` (set a static `uri` on the binding or invoke via a resources/read request)".to_owned();
                                    let downstream = classify_error(&message);
                                    let env = build_result_envelope(
                                        &tool_name,
                                        backend_name,
                                        &profile.database,
                                        None,
                                        None,
                                        false,
                                        started.elapsed().as_millis(),
                                        Some(&downstream),
                                        Some(&message),
                                    );
                                    (env, "clickhouse_error", Some(message))
                                }
                            }
                        }
                        surface::Surface::Prompt => {
                            (surface::prompt_messages_body(&outcome.rows), "ok", None)
                        }
                    }
                }
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "clickhouse_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.database,
                        None,
                        None,
                        false,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("clickhouse.transport".to_owned(), json!("plugin"));
        map
    }

    /// JSON Schema for the result envelope this binding emits. For the catalog
    /// operations the `response.rows` items are typed to the known
    /// `system.tables` / `system.columns` column set; the `query` op leaves rows
    /// untyped (any shape).
    fn output_schema(&self, backend_name: &str) -> Option<Value> {
        let op = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| g.get(backend_name).map(|p| p.operation))
            .unwrap_or(ClickHouseOperation::Query);
        Some(match op {
            ClickHouseOperation::Query => envelope::result_envelope_schema(),
            ClickHouseOperation::ListTables => {
                envelope::catalog_envelope_schema(engine::LIST_TABLES_COLUMNS)
            }
            ClickHouseOperation::ListColumns => {
                envelope::catalog_envelope_schema(engine::LIST_COLUMNS_COLUMNS)
            }
        })
    }

    /// JSON Schema for the tool arguments. The binding's positional `params`
    /// are CEL expressions over `arguments.*`; the referenced argument names
    /// are surfaced as untyped, optional properties. The object stays open
    /// (`additionalProperties: true`) so the schema never rejects valid args.
    fn input_schema(&self, backend_name: &str) -> Option<Value> {
        // `try_read` (sync, non-blocking): `input_schema` is called from the
        // gateway's registration path with no concurrent writer.
        let names: Vec<String> = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| {
                g.get(backend_name).map(|p| {
                    if p.operation.is_catalog() {
                        // Catalog ops take no CEL params; their callable args are
                        // the configured catalog filter argument names.
                        p.catalog_filters.argument_names()
                    } else {
                        arguments_referenced_by_params(&p.compiled_params)
                    }
                })
            })
            .unwrap_or_default();
        Some(params_input_schema(&names))
    }

    /// Enumerate resources for `resources/list` via the operator-fixed
    /// `list_query`. Bindings without one inherit the empty page. The
    /// pagination `?cursor` / `?page_size` are the only non-operator binds:
    /// keyset binds the prior page's last `cursor_column` (NULL first page),
    /// offset binds page_size then the running offset. ClickHouse can bind both,
    /// so the cursor is data — never interpolated.
    async fn list_resources(
        &self,
        backend_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(list_cfg) = profile.list_query.clone() else {
            return Ok(ResourcePage::empty());
        };

        // Bind the cursor + page_size in the order ClickHouse sees the two `?`s
        // for the active mode. Keyset: `(cursor, page_size)`; offset:
        // `(page_size, offset)`.
        let prior_offset = match (list_cfg.mode, cursor) {
            (ListQueryMode::Offset, Some(c)) => {
                c.parse::<u64>().map_err(|_| BackendError::InvalidSpec {
                    message: format!("offset-mode cursor '{c}' is not a non-negative integer"),
                })?
            }
            _ => 0,
        };
        let binds: Vec<ChBind> = match list_cfg.mode {
            ListQueryMode::Keyset => vec![
                match cursor {
                    Some(c) => ChBind::Str(c.to_owned()),
                    None => ChBind::Null,
                },
                ChBind::Int(list_cfg.page_size as i64),
            ],
            ListQueryMode::Offset => vec![
                ChBind::Int(list_cfg.page_size as i64),
                ChBind::Int(prior_offset as i64),
            ],
        };

        let outcome = self
            .run_query(&profile, &list_cfg.sql, binds, list_cfg.page_size as usize)
            .await
            .map_err(|message| BackendError::Transport { message })?;

        Ok(surface::rows_to_resource_page(
            &outcome.rows,
            &list_cfg,
            prior_offset,
        ))
    }

    /// Return completion candidates for a resource-template variable via the
    /// operator-fixed `variable_completions[<variable_name>]` query. The single
    /// `?` is bound to the caller's typed `prefix` value — never interpolated
    /// (injection-safe). Unconfigured variables inherit the empty list.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(cc) = profile.variable_completions.get(variable_name).cloned() else {
            return Ok(vec![]);
        };

        let max = cc.max_results.unwrap_or(100) as usize;
        let binds = vec![ChBind::Str(prefix.to_owned())];
        let outcome = self
            .run_query(&profile, &cc.sql, binds, max)
            .await
            .map_err(|message| BackendError::Transport { message })?;

        let first_col = outcome
            .rows
            .first()
            .and_then(Value::as_object)
            .and_then(|m| m.keys().next().cloned());
        Ok(surface::rows_to_completion_values(
            &outcome.rows,
            first_col.as_deref(),
            max,
        ))
    }
}

/// Collect the distinct `arguments.<ident>` names referenced across a
/// binding's compiled CEL params, preserving first-seen order.
fn arguments_referenced_by_params(params: &[CompiledParam]) -> Vec<String> {
    let mut names = Vec::new();
    for p in params {
        for name in extract_argument_idents(&p.source) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Build an open object schema from the referenced argument names. With no
/// known names this is the permissive `{type:object, additionalProperties:true}`.
fn params_input_schema(names: &[String]) -> Value {
    let mut properties = serde_json::Map::new();
    for name in names {
        properties.insert(name.clone(), json!({}));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "additionalProperties": true,
    })
}

/// Extract identifiers appearing as `arguments.<ident>` in a CEL source string.
/// Pure string scan (no CEL deps) — a best-effort hint, never a rejection
/// surface.
fn extract_argument_idents(source: &str) -> Vec<String> {
    const MARKER: &str = "arguments.";
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(MARKER) {
        let start = search_from + rel + MARKER.len();
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            out.push(source[start..end].to_owned());
        }
        search_from = end.max(search_from + rel + MARKER.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        mcpg_plugin_protocol::noop_backend_host()
    }

    fn minimal_spec() -> Value {
        json!({
            "url": "http://localhost:8123",
            "statement": "SELECT 1 AS one WHERE 1 = ?",
            "params": ["arguments.id"],
        })
    }

    #[test]
    fn kind_is_clickhouse() {
        assert_eq!(ClickHouseBackendPlugin::new().kind(), "clickhouse");
    }

    #[test]
    fn manifest_id() {
        assert_eq!(
            ClickHouseBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.clickhouse"
        );
    }

    #[test]
    fn extract_argument_idents_finds_names() {
        let got = extract_argument_idents("arguments.user_id + size(arguments.tags)");
        assert_eq!(got, vec!["user_id".to_owned(), "tags".to_owned()]);
        assert!(extract_argument_idents("1 + 2").is_empty());
    }

    #[tokio::test]
    async fn output_schema_is_object() {
        let plugin = ClickHouseBackendPlugin::new();
        let schema = BackendPlugin::output_schema(&plugin, "an").unwrap();
        assert_eq!(schema["type"], json!("object"));
    }

    #[tokio::test]
    async fn input_schema_lists_referenced_params() {
        let plugin = ClickHouseBackendPlugin::new();
        plugin
            .register_profile("an", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "an").unwrap();
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["additionalProperties"], json!(true));
        assert!(schema["properties"]["id"].is_object());
    }

    /// The client builds at register without opening a socket — registration
    /// stays offline and returns synchronously.
    #[tokio::test]
    async fn register_builds_client_without_connecting() {
        let plugin = ClickHouseBackendPlugin::new();
        plugin
            .register_profile("an", &minimal_spec(), no_op_host())
            .await
            .expect("register stays offline");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("an").unwrap();
        assert_eq!(p.database, DEFAULT_DATABASE);
        assert!(p.read_only);
        assert_eq!(p.compiled_params.len(), 1);
    }

    #[tokio::test]
    async fn register_carries_explicit_database_label() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["database"] = json!("analytics");
        plugin
            .register_profile("an", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert_eq!(profiles.get("an").unwrap().database, "analytics");
    }

    #[tokio::test]
    async fn register_rejects_verify_peer_false() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["tls"] = json!({ "verify_peer": false });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("verify_peer=false");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("verify_peer=false"), "{message}");
                assert!(message.contains("trusted CA"), "{message}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_rejects_non_read_only_when_guarded() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("INSERT INTO t VALUES (1)");
        spec["params"] = json!([]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-select under read_only");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_allows_write_when_read_only_off() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("INSERT INTO t VALUES (?)");
        spec["query"] = json!({ "read_only": false });
        plugin
            .register_profile("w", &spec, no_op_host())
            .await
            .expect("write under read_only=false");
        assert!(!plugin.profiles.read().await.get("w").unwrap().read_only);
    }

    #[tokio::test]
    async fn register_rejects_bare_cred() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("SELECT 1 WHERE secret = 'cred://aws/x#id'");
        spec["params"] = json!([]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bare cred");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_empty_statement() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("   ");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty statement");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_uri_on_tool_surface() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["uri"] = json!("clickhouse://x");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("uri on tool surface");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_keyset_list_query_without_cursor() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["surface"] = json!("resource");
        spec["list_query"] = json!({ "sql": "SELECT id AS uri FROM t" });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("missing cursor_column");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = ClickHouseBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    /// A bad-param call (CEL references a missing path) returns a tool-error
    /// envelope (downstreamError set), not a transport `Err`.
    #[tokio::test]
    async fn execute_param_failure_yields_error_envelope() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "statement": "SELECT ? AS x",
            "params": ["arguments.missing.deeply"],
        });
        plugin
            .register_profile("q", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: serde_json::to_vec(&json!({})).unwrap(),
            headers: vec![("mcpg-tool-name".into(), "q".into())],
            request_id: "rq".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("q", req).await.expect("execute");
        let env: Value = serde_json::from_slice(&resp.payload).expect("envelope json");
        assert!(!env["downstreamError"].is_null(), "{env}");
        assert!(env["response"].is_null());
    }

    #[tokio::test]
    async fn register_list_tables_without_statement() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "operation": "list_tables",
            "catalog_database": "analytics",
        });
        plugin
            .register_profile("lt", &spec, no_op_host())
            .await
            .expect("list_tables registers without a statement");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("lt").unwrap();
        assert_eq!(p.operation, ClickHouseOperation::ListTables);
        assert_eq!(p.catalog_filters.database.as_deref(), Some("analytics"));
    }

    #[tokio::test]
    async fn register_list_columns_requires_table() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "operation": "list_columns",
        });
        let err = plugin
            .register_profile("lc", &spec, no_op_host())
            .await
            .expect_err("list_columns needs a table filter");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("catalog_table"), "{message}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_list_columns_with_table_arg() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "operation": "list_columns",
            "catalog_table_arg": "tbl",
        });
        plugin
            .register_profile("lc", &spec, no_op_host())
            .await
            .expect("table_arg satisfies the list_columns requirement");
        let profiles = plugin.profiles.read().await;
        assert_eq!(
            profiles
                .get("lc")
                .unwrap()
                .catalog_filters
                .table_arg
                .as_deref(),
            Some("tbl")
        );
    }

    #[tokio::test]
    async fn register_stores_query_settings() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["query"] = json!({ "settings": { "max_threads": "4", "readonly": "2" } });
        plugin
            .register_profile("s", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let s = &profiles.get("s").unwrap().settings;
        assert!(s.iter().any(|(k, v)| k == "max_threads" && v == "4"));
        assert!(s.iter().any(|(k, v)| k == "readonly" && v == "2"));
    }

    #[tokio::test]
    async fn output_schema_for_list_tables_types_rows() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "operation": "list_tables",
        });
        plugin
            .register_profile("lt", &spec, no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::output_schema(&plugin, "lt").unwrap();
        let item = &schema["properties"]["response"]["properties"]["rows"]["items"];
        assert_eq!(item["type"], json!("object"));
        assert!(item["properties"]["engine"].is_object());
    }

    #[tokio::test]
    async fn input_schema_for_catalog_lists_filter_args() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "operation": "list_columns",
            "catalog_table_arg": "tbl",
            "catalog_database_arg": "db",
        });
        plugin
            .register_profile("lc", &spec, no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "lc").unwrap();
        assert!(schema["properties"]["tbl"].is_object());
        assert!(schema["properties"]["db"].is_object());
    }

    #[test]
    fn resolve_one_arg_overrides_static() {
        let args = json!({ "tbl": "events" });
        assert_eq!(
            resolve_one(Some("fallback"), Some("tbl"), &args).as_deref(),
            Some("events")
        );
        // Argument absent → static value.
        assert_eq!(
            resolve_one(Some("fallback"), Some("missing"), &args).as_deref(),
            Some("fallback")
        );
        // No static, no arg → None (match all).
        assert_eq!(resolve_one(None, None, &args), None);
    }

    #[tokio::test]
    async fn list_resources_empty_when_unconfigured() {
        let plugin = ClickHouseBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let page = BackendPlugin::list_resources(&plugin, "q", None)
            .await
            .expect("list");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    /// A resource_template binding may declare a per-`{id}` `read_query` and omit
    /// `statement`; the profile stores it and stays read-only-guarded.
    #[tokio::test]
    async fn register_resource_template_read_query() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "surface": "resource",
            "read_query": "SELECT * FROM orders WHERE id = ?",
            "params": ["arguments.id"],
        });
        plugin
            .register_profile("rt", &spec, no_op_host())
            .await
            .expect("read_query registers without a statement");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("rt").unwrap();
        assert_eq!(
            p.read_query.as_deref(),
            Some("SELECT * FROM orders WHERE id = ?")
        );
        assert!(p.statement.is_empty());
        assert_eq!(p.surface, surface::Surface::Resource);
        assert_eq!(p.compiled_params.len(), 1);
    }

    #[tokio::test]
    async fn register_rejects_read_query_on_tool_surface() {
        let plugin = ClickHouseBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["read_query"] = json!("SELECT * FROM t WHERE id = ?");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("read_query on tool surface");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("read_query"), "{message}");
                assert!(message.contains("surface: resource"), "{message}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_rejects_non_read_only_read_query() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "surface": "resource",
            "read_query": "DELETE FROM orders WHERE id = ?",
            "params": ["arguments.id"],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-read-only read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_bare_cred_read_query() {
        let plugin = ClickHouseBackendPlugin::new();
        let spec = json!({
            "url": "http://localhost:8123",
            "surface": "resource",
            "read_query": "SELECT * FROM t WHERE k = 'cred://aws/x#id'",
            "params": [],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bare cred in read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// The gateway delivers the extracted template variable as `arguments.<var>`;
    /// the binding's `params` CEL bind it to the `read_query`'s `?` placeholder.
    /// A value crafted to look like SQL is carried verbatim as a single scalar
    /// bind (a `ChBind::Str`) — it is data for the driver to escape, never spliced
    /// into the statement text.
    #[test]
    fn template_var_binds_as_param_not_interpolated() {
        let compiled = params::compile_params(&["arguments.id".to_owned()]).unwrap();
        // What the gateway hands the backend for `clickhouse://orders/{id}` on a
        // read of `clickhouse://orders/1 OR 1=1; DROP TABLE orders`.
        let injection = "1 OR 1=1; DROP TABLE orders";
        let args = json!({
            "uri": format!("clickhouse://orders/{injection}"),
            "id": injection,
            "template_vars": { "id": injection },
        });
        let values = params::evaluate_params(&compiled, &args).unwrap();
        assert_eq!(values, vec![json!(injection)]);
        let bind = params::json_to_ch_bind(values.into_iter().next().unwrap()).unwrap();
        // The whole injection string is one opaque scalar bind — the driver
        // escapes it as a ClickHouse string literal; it never reaches SQL as text.
        assert_eq!(bind, params::ChBind::Str(injection.to_owned()));
    }

    /// The resource-read branch shapes a single fabricated row into the
    /// `resources/read` contract body keyed on the concrete (gateway-supplied)
    /// URI.
    #[test]
    fn resource_template_read_shapes_single_row_contents() {
        let uri = "clickhouse://orders/42";
        let row = json!({ "id": 42, "total": 19.99 });
        let body = surface::resource_contents_body(uri, std::slice::from_ref(&row));
        let contents = body["contents"].as_array().expect("contents");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!(uri));
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let decoded: Vec<Value> =
            serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, vec![row]);
    }

    #[tokio::test]
    async fn complete_template_variable_empty_when_unconfigured() {
        let plugin = ClickHouseBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "q",
            "v",
            "x",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert!(got.is_empty());
    }
}
