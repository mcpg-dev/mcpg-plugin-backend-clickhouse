//! Operator-facing spec for the ClickHouse backend plugin.
//!
//! One binding = one operator-fixed analytical statement = one MCP tool (or
//! resource). The server connection (`url` / `database` / `auth` / `tls`), the
//! read-only guard, the statement and the query bounds all live on the
//! per-binding spec, mirroring the duckdb/snowflake one-profile-per-binding
//! shape.

use serde::Deserialize;

/// HTTP basic auth for the ClickHouse server. The password is resolved from
/// `${cred://…}` / `${env.X}` at config load (a bare `cred://` is rejected at
/// register — see `lib.rs`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClickHouseAuth {
    /// ClickHouse user (defaults to `default` when omitted).
    #[serde(default)]
    pub username: Option<String>,
    /// ClickHouse password (config-resolved). Empty/omitted = no password.
    #[serde(default)]
    pub password: Option<String>,
}

/// TLS knobs. The driver verifies the server certificate by default (rustls +
/// webpki roots). `verify_peer = false` opts into an insecure no-verify client
/// — for self-signed dev servers only.
#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseTls {
    /// Verify the server's TLS certificate chain + hostname. Default true.
    #[serde(default = "default_verify_peer")]
    pub verify_peer: bool,
}

impl Default for ClickHouseTls {
    fn default() -> Self {
        Self {
            verify_peer: default_verify_peer(),
        }
    }
}

/// Query-execution bounds.
#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseQueryConfig {
    /// Per-call ceiling (ms) on the whole request (default 30 s). Enforced both
    /// as the outer tokio timeout AND as the server-side `max_execution_time`
    /// setting (seconds, rounded up).
    #[serde(default = "default_max_execution_time_ms")]
    pub max_execution_time_ms: u64,

    /// Client-side cap on returned rows (default 100000). Extra rows set the
    /// envelope `truncated` flag.
    #[serde(default = "default_max_result_rows")]
    pub max_result_rows: usize,

    /// Read-only guard. When true (default) the operator-fixed statement must
    /// begin with a read-only keyword (SELECT / WITH / SHOW / DESCRIBE /
    /// EXPLAIN) at register AND the server-side `readonly=1` setting is applied
    /// per query. Set false to allow writes (operator responsibility).
    #[serde(default = "default_read_only")]
    pub read_only: bool,

    /// Operator-fixed ClickHouse query settings applied per query via the
    /// driver's `.with_option(k, v)`. Keys are setting names, values their string
    /// form (ClickHouse parses the string). Intended for guardrails such as
    /// `readonly`, `max_execution_time`, `max_threads`, `max_memory_usage`,
    /// `max_result_rows`. Operator-config ONLY — never caller-supplied — so a
    /// caller can never widen a setting (e.g. flip `readonly` off). When the
    /// read-only guard sets `readonly=1` and `max_execution_time` from the
    /// timeout, an explicit entry here overrides those defaults.
    #[serde(default)]
    pub settings: std::collections::BTreeMap<String, String>,
}

impl Default for ClickHouseQueryConfig {
    fn default() -> Self {
        Self {
            max_execution_time_ms: default_max_execution_time_ms(),
            max_result_rows: default_max_result_rows(),
            read_only: default_read_only(),
            settings: std::collections::BTreeMap::new(),
        }
    }
}

fn default_max_execution_time_ms() -> u64 {
    30_000
}
fn default_max_result_rows() -> usize {
    100_000
}
fn default_read_only() -> bool {
    true
}
fn default_verify_peer() -> bool {
    true
}

/// Operator-facing spec the gateway serializes when calling `register_profile`.
/// Mirrors `ClickHouseBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseBackendSpec {
    /// Which operation this binding performs. `query` (default) runs the
    /// operator-fixed `statement` with `?` binds. `list_tables` / `list_columns`
    /// are read-only catalog-introspection operations that query ClickHouse's
    /// `system.tables` / `system.columns` for schema discovery. The catalog
    /// operations ignore `statement` / `params` (they build their own bound
    /// SELECT) and never mutate, so the read-only guard does not apply.
    #[serde(default)]
    pub operation: ClickHouseOperation,

    /// ClickHouse HTTP endpoint URL (e.g. `https://host:8443` for Cloud /
    /// `http://host:8123` for OSS). Operator-configured (never caller-templated),
    /// so there is no SSRF vector on the URL itself.
    pub url: String,

    /// Target database (defaults to `default` when omitted).
    #[serde(default)]
    pub database: Option<String>,

    /// Static database-name filter for the catalog operations (`list_tables` /
    /// `list_columns`). Bound as a parameter (`WHERE database = ?`), never
    /// interpolated. Omitted → no database filter (all databases).
    #[serde(default)]
    pub catalog_database: Option<String>,

    /// Per-call argument name supplying the database filter for the catalog
    /// operations. When set AND present as a string in the call arguments it
    /// overrides `catalog_database`. Bound as a parameter — caller input can only
    /// narrow the metadata, never alter the catalog query.
    #[serde(default)]
    pub catalog_database_arg: Option<String>,

    /// Static table-name filter for `list_columns` (the table whose columns to
    /// list). Bound as a parameter (`WHERE table = ?`), never interpolated.
    #[serde(default)]
    pub catalog_table: Option<String>,

    /// Per-call argument name supplying the table filter for `list_columns`. When
    /// set AND present as a string it overrides `catalog_table`. Bound as a
    /// parameter.
    #[serde(default)]
    pub catalog_table_arg: Option<String>,

    /// HTTP basic auth (username + config-resolved password).
    #[serde(default)]
    pub auth: ClickHouseAuth,

    /// TLS knobs (certificate verification).
    #[serde(default)]
    pub tls: ClickHouseTls,

    /// The operator-fixed statement. Uses `?` positional bind placeholders
    /// bound from `params`. The statement text is operator-fixed — it is NOT
    /// templated from caller arguments. A literal `?` is escaped as `??`.
    /// Required for `operation: query`; ignored (and may be omitted) for the
    /// catalog operations, which build their own bound SELECT.
    #[serde(default)]
    pub statement: String,

    /// Ordered CEL expressions; `params[i]` → the i-th `?`. Each is evaluated
    /// against the call arguments (`arguments.*`) and bound as an escaped
    /// ClickHouse SQL literal — injection-safe.
    #[serde(default)]
    pub params: Vec<String>,

    /// Query-execution bounds (timeout, max rows, read-only guard). A bare
    /// `query:` or an omitted block applies all defaults.
    #[serde(default)]
    pub query: ClickHouseQueryConfig,

    /// MCP surface this binding serves. `tool` (default) emits the unchanged
    /// tool envelope; `resource` reshapes successful rows into the
    /// `resources/read` `{contents:[…]}` body; `prompt` reshapes them into the
    /// `prompts/get` `{messages:[…]}` body. Set to match the capability list the
    /// binding is placed under (`resources[]` / `prompts[]`).
    #[serde(default)]
    pub surface: crate::surface::Surface,

    /// Optional static resource URI for `surface: resource`. When set it is used
    /// verbatim as the emitted content `uri`; when omitted the binding uses the
    /// requested URI the gateway passes in the call arguments (`uri`). Ignored
    /// for `tool` / `prompt` surfaces.
    #[serde(default)]
    pub uri: Option<String>,

    /// Optional listing statement for `resources/list`. On a
    /// `surface: resource` binding this runs at list time to enumerate concrete
    /// resource URIs. Operator-fixed; the only caller-derived inputs are the
    /// paginated `?cursor` / `?page_size` binds. Empty → the binding returns no
    /// dynamic listing (the trait default).
    #[serde(default)]
    pub list_query: Option<ListQueryConfig>,

    /// Optional per-`{id}` single-row read statement for a `resource_templates[]`
    /// binding (`surface: resource` with a `uri_template` like
    /// `clickhouse://orders/{id}`). On a `resources/read` of a concrete URI the
    /// gateway extracts the template variables and supplies them in the call
    /// arguments (each `{var}` as `arguments.<var>`); this statement's `?`
    /// placeholders are bound from the binding's `params` CEL expressions
    /// (`arguments.<var>`), so the extracted value binds SERVER-SIDE as a query
    /// parameter — never interpolated into SQL (injection-safe). When omitted the
    /// resource-read branch falls back to `statement`. Operator-fixed; required
    /// to be read-only under the read-only guard.
    #[serde(default)]
    pub read_query: Option<String>,

    /// Optional per-template-variable completion config for
    /// `completion/complete`. Keyed by the URI template variable name; each
    /// entry is an operator-fixed query whose single `?` is bound to the
    /// caller-typed prefix (never interpolated — injection-safe). Empty → no
    /// completion candidates (the trait default).
    #[serde(default)]
    pub variable_completions: std::collections::BTreeMap<String, CompletionConfig>,
}

/// The operation a binding performs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClickHouseOperation {
    /// Run the operator-fixed `statement` with `?` binds (the default).
    #[default]
    Query,
    /// Discover tables/views via `system.tables` (database / name / engine /
    /// total_rows / total_bytes).
    ListTables,
    /// Discover a table's columns via `system.columns` (database / table / name /
    /// type / position / default_kind).
    ListColumns,
}

impl ClickHouseOperation {
    /// Lowercase wire token (matches the `serde` rename).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClickHouseOperation::Query => "query",
            ClickHouseOperation::ListTables => "list_tables",
            ClickHouseOperation::ListColumns => "list_columns",
        }
    }

    /// Whether this is a catalog-introspection operation (inherently read-only,
    /// driven by `system.tables` / `system.columns`, not the `statement`).
    #[must_use]
    pub fn is_catalog(self) -> bool {
        matches!(
            self,
            ClickHouseOperation::ListTables | ClickHouseOperation::ListColumns
        )
    }
}

/// Pagination strategy for [`ListQueryConfig`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListQueryMode {
    /// `WHERE cursor_column > ? ORDER BY cursor_column LIMIT ?`. The first `?`
    /// is the keyset cursor (NULL on the first page); the second is page_size.
    #[default]
    Keyset,
    /// `LIMIT ? OFFSET ?` — the first `?` is page_size, the second the offset.
    Offset,
}

/// Operator-fixed listing statement + pagination shape for `resources/list`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListQueryConfig {
    /// SELECT that returns one row per enumerable resource. Required column:
    /// `uri`. Optional columns: `name`, `description`, `mime_type`. The
    /// statement is operator-fixed; the pagination binds (`?cursor` /
    /// `?page_size`) are the only non-operator values.
    pub sql: String,
    /// Pagination mode — `keyset` (default) or `offset`.
    #[serde(default)]
    pub mode: ListQueryMode,
    /// Column the keyset cursor tracks (typically `id` or `updated_at`).
    /// Required for `mode: keyset`; ignored for `mode: offset`.
    #[serde(default)]
    pub cursor_column: Option<String>,
    /// Rows per page (1..=1000). Defaults to 100.
    #[serde(default = "default_list_page_size")]
    pub page_size: u64,
}

/// Operator-fixed completion query for one template variable.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompletionConfig {
    /// SQL returning candidate values in its first column. MUST reference a
    /// single `?` placeholder — bound to the caller-typed prefix at call time
    /// (e.g. `SELECT name FROM repos WHERE name LIKE concat(?, '%') LIMIT 100`).
    pub sql: String,
    /// Optional cap on returned candidates; defaults to 100.
    #[serde(default)]
    pub max_results: Option<u32>,
}

fn default_list_page_size() -> u64 {
    100
}

/// Read-only / safe-identifier validation for an operator-fixed
/// [`ListQueryConfig`]. Fail-closed at register so misconfig never reaches a
/// `resources/list` call.
pub fn validate_list_query(cfg: &ListQueryConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err("list_query.sql must not be empty".into());
    }
    if cfg.page_size == 0 || cfg.page_size > 1_000 {
        return Err(format!(
            "list_query.page_size ({}) must be in 1..=1000",
            cfg.page_size
        ));
    }
    if cfg.mode == ListQueryMode::Keyset {
        let col = cfg.cursor_column.as_deref().unwrap_or("").trim();
        if col.is_empty() {
            return Err("list_query.cursor_column is required for mode: keyset".into());
        }
        if !is_safe_sql_identifier(col) {
            return Err(format!(
                "list_query.cursor_column '{col}' is not a safe SQL identifier"
            ));
        }
    }
    Ok(())
}

/// Validate an operator-fixed [`CompletionConfig`]: non-empty SQL referencing
/// exactly one `?` placeholder (the bound prefix). A literal `?` is written as
/// `??`, so escaped pairs are not counted as binds.
pub fn validate_completion(name: &str, cfg: &CompletionConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err(format!("variable_completions.{name}.sql must not be empty"));
    }
    if count_bind_placeholders(&cfg.sql) != 1 {
        return Err(format!(
            "variable_completions.{name}.sql must reference exactly one `?` placeholder (bound to the typed prefix)"
        ));
    }
    Ok(())
}

/// Count `?` bind placeholders, treating `??` as one escaped literal `?` (the
/// driver's escape convention) rather than two binds.
pub fn count_bind_placeholders(sql: &str) -> usize {
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut binds = 0;
    while i < bytes.len() {
        if bytes[i] == b'?' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'?' {
                // Escaped literal `?` — skip both, count zero binds.
                i += 2;
                continue;
            }
            binds += 1;
        }
        i += 1;
    }
    binds
}

/// A safe SQL identifier — `[A-Za-z_][A-Za-z0-9_]*`. Used to fence the
/// operator-declared keyset `cursor_column`, which is interpolated into the
/// next-cursor projection.
fn is_safe_sql_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_applies_defaults_when_omitted() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "statement": "SELECT 1 AS one",
        }))
        .unwrap();
        assert!(spec.query.read_only);
        assert_eq!(spec.query.max_execution_time_ms, 30_000);
        assert_eq!(spec.query.max_result_rows, 100_000);
        assert!(spec.tls.verify_peer);
        assert!(spec.database.is_none());
        assert!(spec.auth.username.is_none());
        assert!(spec.params.is_empty());
    }

    #[test]
    fn parses_overrides_and_auth() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "https://ch.example:8443",
            "database": "analytics",
            "auth": { "username": "reader", "password": "s3cr3t" },
            "tls": { "verify_peer": false },
            "statement": "SELECT * FROM events WHERE id = ?",
            "params": ["arguments.id"],
            "query": { "max_execution_time_ms": 5000, "max_result_rows": 50, "read_only": false },
        }))
        .unwrap();
        assert_eq!(spec.database.as_deref(), Some("analytics"));
        assert_eq!(spec.auth.username.as_deref(), Some("reader"));
        assert_eq!(spec.auth.password.as_deref(), Some("s3cr3t"));
        assert!(!spec.tls.verify_peer);
        assert!(!spec.query.read_only);
        assert_eq!(spec.query.max_execution_time_ms, 5000);
        assert_eq!(spec.query.max_result_rows, 50);
    }

    #[test]
    fn operation_defaults_to_query() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "statement": "SELECT 1 AS one",
        }))
        .unwrap();
        assert_eq!(spec.operation, ClickHouseOperation::Query);
        assert!(!spec.operation.is_catalog());
        assert_eq!(spec.operation.as_str(), "query");
    }

    #[test]
    fn parses_list_tables_operation_with_filter() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "operation": "list_tables",
            "catalog_database": "analytics",
            "catalog_database_arg": "db",
        }))
        .unwrap();
        assert_eq!(spec.operation, ClickHouseOperation::ListTables);
        assert!(spec.operation.is_catalog());
        assert_eq!(spec.operation.as_str(), "list_tables");
        assert_eq!(spec.catalog_database.as_deref(), Some("analytics"));
        assert_eq!(spec.catalog_database_arg.as_deref(), Some("db"));
        // `statement` may be omitted for catalog operations.
        assert!(spec.statement.is_empty());
    }

    #[test]
    fn parses_list_columns_operation() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "operation": "list_columns",
            "catalog_table": "events",
            "catalog_table_arg": "tbl",
        }))
        .unwrap();
        assert_eq!(spec.operation, ClickHouseOperation::ListColumns);
        assert!(spec.operation.is_catalog());
        assert_eq!(spec.catalog_table.as_deref(), Some("events"));
        assert_eq!(spec.catalog_table_arg.as_deref(), Some("tbl"));
    }

    #[test]
    fn parses_query_settings() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "statement": "SELECT 1 AS one",
            "query": {
                "settings": { "max_threads": "4", "max_memory_usage": "1000000000" },
            },
        }))
        .unwrap();
        assert_eq!(
            spec.query.settings.get("max_threads").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            spec.query
                .settings
                .get("max_memory_usage")
                .map(String::as_str),
            Some("1000000000")
        );
    }

    #[test]
    fn parses_list_query_and_completions() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "statement": "SELECT 1 AS one",
            "surface": "resource",
            "list_query": {
                "sql": "SELECT id AS uri FROM t WHERE id > ? ORDER BY id LIMIT ?",
                "cursor_column": "id",
                "page_size": 50,
            },
            "variable_completions": {
                "name": { "sql": "SELECT name FROM t WHERE name LIKE concat(?, '%') LIMIT 100" },
            },
        }))
        .unwrap();
        let lq = spec.list_query.expect("list_query");
        assert_eq!(lq.page_size, 50);
        assert_eq!(lq.mode, ListQueryMode::Keyset);
        assert_eq!(lq.cursor_column.as_deref(), Some("id"));
        assert!(spec.variable_completions.contains_key("name"));
    }

    #[test]
    fn parses_resource_template_read_query() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "surface": "resource",
            "read_query": "SELECT * FROM orders WHERE id = ?",
            "params": ["arguments.id"],
        }))
        .unwrap();
        assert_eq!(
            spec.read_query.as_deref(),
            Some("SELECT * FROM orders WHERE id = ?")
        );
        // `statement` may be omitted when `read_query` carries the read.
        assert!(spec.statement.is_empty());
        assert_eq!(spec.params, vec!["arguments.id".to_owned()]);
    }

    #[test]
    fn read_query_defaults_to_none() {
        let spec: ClickHouseBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "http://localhost:8123",
            "statement": "SELECT 1 AS one",
        }))
        .unwrap();
        assert!(spec.read_query.is_none());
    }

    #[test]
    fn validate_list_query_enforces_bounds_and_cursor() {
        let mut cfg = ListQueryConfig {
            sql: "SELECT id AS uri FROM t".into(),
            mode: ListQueryMode::Keyset,
            cursor_column: None,
            page_size: 100,
        };
        assert!(
            validate_list_query(&cfg).is_err(),
            "keyset needs cursor_column"
        );
        cfg.cursor_column = Some("id".into());
        assert!(validate_list_query(&cfg).is_ok());
        cfg.cursor_column = Some("id; DROP TABLE t".into());
        assert!(
            validate_list_query(&cfg).is_err(),
            "unsafe cursor identifier"
        );
        cfg.cursor_column = Some("id".into());
        cfg.page_size = 0;
        assert!(validate_list_query(&cfg).is_err(), "page_size out of range");
        cfg.page_size = 100;
        cfg.sql = "  ".into();
        assert!(validate_list_query(&cfg).is_err(), "empty sql");
    }

    #[test]
    fn validate_list_query_offset_mode_skips_cursor() {
        let cfg = ListQueryConfig {
            sql: "SELECT id AS uri FROM t LIMIT ? OFFSET ?".into(),
            mode: ListQueryMode::Offset,
            cursor_column: None,
            page_size: 100,
        };
        assert!(validate_list_query(&cfg).is_ok());
    }

    #[test]
    fn validate_completion_requires_single_placeholder() {
        let mut cc = CompletionConfig {
            sql: "SELECT name FROM t WHERE name LIKE concat(?, '%')".into(),
            max_results: None,
        };
        assert!(validate_completion("name", &cc).is_ok());
        cc.sql = "SELECT name FROM t".into();
        assert!(validate_completion("name", &cc).is_err(), "needs one ?");
        cc.sql = "SELECT name FROM t WHERE a = ? AND b = ?".into();
        assert!(validate_completion("name", &cc).is_err(), "exactly one ?");
        cc.sql = "  ".into();
        assert!(validate_completion("name", &cc).is_err(), "empty sql");
    }

    #[test]
    fn count_bind_placeholders_ignores_escaped_pairs() {
        assert_eq!(count_bind_placeholders("SELECT ? FROM t"), 1);
        assert_eq!(count_bind_placeholders("SELECT '??' FROM t WHERE x = ?"), 1);
        assert_eq!(count_bind_placeholders("SELECT '??' FROM t"), 0);
        assert_eq!(count_bind_placeholders("a = ? AND b = ?"), 2);
    }
}
