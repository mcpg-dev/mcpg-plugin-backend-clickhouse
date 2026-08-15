//! ClickHouse transport: an async statement runner over the official
//! `clickhouse` crate (HTTP interface, hyper transport), the read-only keyword
//! guard, and the JSONEachRow → JSON marshaller.
//!
//! The `clickhouse::Client` is built once at `register_profile` — it is I/O-free
//! configuration (`with_url`/`with_user`/`with_password`/`with_database` do NOT
//! open a socket) and internally connection-pooled (hyper keeps the connection
//! pool), so there is no per-call connect and no deadpool. The profile clones
//! the cheap `Client` (an `Arc` of the HTTP client + small config) per call. TLS
//! always verifies the server certificate (the crate's default rustls
//! connector); a binding that disables verification is rejected at register.
//!
//! Each call runs `client.query(sql).bind(..).fetch_bytes("JSONEachRow")`,
//! collects the response bytes, and parses the NDJSON stream — one JSON object
//! per line — into capped JSON rows. The typed `#[derive(Row)]` path is NOT
//! used (rows are dynamic).

use std::time::Duration;

use clickhouse::Client;
use serde_json::Value;

use crate::params::ChBind;

/// Outcome of a completed query: the JSON rows (capped at `max_rows`) plus
/// whether more rows existed beyond the cap.
#[derive(Debug)]
pub struct QueryOutcome {
    pub rows: Vec<Value>,
    pub truncated: bool,
    pub row_count: usize,
}

/// Column set a `list_tables` catalog query yields (from `system.tables`).
pub const LIST_TABLES_COLUMNS: &[&str] =
    &["database", "name", "engine", "total_rows", "total_bytes"];

/// Column set a `list_columns` catalog query yields (from `system.columns`).
pub const LIST_COLUMNS_COLUMNS: &[&str] = &[
    "database",
    "table",
    "name",
    "type",
    "position",
    "default_kind",
];

/// A built catalog-introspection query: an operator-fixed SELECT against a
/// ClickHouse `system.*` table plus the ordered `?` binds (the optional
/// filters). The filters are ALWAYS bound parameters — never interpolated — so
/// caller input can only narrow the metadata, never alter the catalog query.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogQuery {
    pub sql: String,
    pub binds: Vec<ChBind>,
}

/// Build the `list_tables` query over `system.tables`. An optional `database`
/// filter is appended as a bound `WHERE database = ?` clause (never
/// interpolated); an empty/None filter lists tables across all databases. Rows
/// are ordered for a stable listing and capped server-side by `LIMIT`.
pub fn build_list_tables_query(database: Option<&str>, max_rows: usize) -> CatalogQuery {
    let mut sql =
        String::from("SELECT database, name, engine, total_rows, total_bytes FROM system.tables");
    let mut binds = Vec::new();
    if let Some(db) = nonempty(database) {
        sql.push_str(" WHERE database = ?");
        binds.push(ChBind::Str(db.to_owned()));
    }
    sql.push_str(" ORDER BY database, name LIMIT ?");
    binds.push(ChBind::Int(max_rows as i64));
    CatalogQuery { sql, binds }
}

/// Build the `list_columns` query over `system.columns`. An optional `table`
/// filter and an optional `database` filter are each appended as bound
/// `WHERE`/`AND` predicates (never interpolated). Rows are ordered by position
/// for a stable column listing and capped server-side by `LIMIT`.
pub fn build_list_columns_query(
    database: Option<&str>,
    table: Option<&str>,
    max_rows: usize,
) -> CatalogQuery {
    let mut sql = String::from(
        "SELECT database, table, name, type, position, default_kind FROM system.columns",
    );
    let mut binds = Vec::new();
    let mut predicates = Vec::new();
    if let Some(db) = nonempty(database) {
        predicates.push("database = ?");
        binds.push(ChBind::Str(db.to_owned()));
    }
    if let Some(tbl) = nonempty(table) {
        predicates.push("table = ?");
        binds.push(ChBind::Str(tbl.to_owned()));
    }
    if !predicates.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&predicates.join(" AND "));
    }
    sql.push_str(" ORDER BY database, table, position LIMIT ?");
    binds.push(ChBind::Int(max_rows as i64));
    CatalogQuery { sql, binds }
}

/// Trim a filter to `None` when empty/whitespace, else `Some(trimmed)`.
fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

/// Reject a statement that is not read-only. Delegates to the shared, hardened
/// guard so every SQL-ish backend enforces the same policy: a read-only leading
/// keyword, no write/DDL token anywhere (catches data-modifying CTEs and
/// `EXPLAIN ANALYZE`), and a single statement only.
pub fn enforce_read_only(statement: &str) -> Result<(), String> {
    mcpg_plugin_sdk::sql_guard::enforce_read_only(statement)
}

/// Build the per-binding `clickhouse::Client`. This is I/O-free: it only stores
/// the URL / credentials / database / per-query options — no socket is opened
/// until the first query. Always the crate's default verifying client, whose
/// rustls connector verifies the server certificate chain + hostname against
/// the webpki roots. There is no certificate-verification opt-out: a binding
/// that sets `tls.verify_peer = false` is rejected at `register_profile`.
pub fn build_client(
    url: &str,
    database: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Client {
    let mut client = Client::default().with_url(url);
    if let Some(db) = database {
        client = client.with_database(db);
    }
    if let Some(user) = username {
        client = client.with_user(user);
    }
    if let Some(pw) = password {
        client = client.with_password(pw);
    }
    client
}

/// Lower a scalar bind onto a `clickhouse::Query` via `.bind`. The driver
/// escapes + serializes each value as a ClickHouse SQL literal (strings get
/// single-quote-escaped), so the bound value can never alter the statement.
/// A NULL binds as the SQL literal `NULL`.
fn bind_value(query: clickhouse::query::Query, value: &ChBind) -> clickhouse::query::Query {
    match value {
        // `Option::<i64>::None` serializes to the SQL literal `NULL`.
        ChBind::Null => query.bind(Option::<i64>::None),
        ChBind::Int(i) => query.bind(*i),
        ChBind::Float(f) => query.bind(*f),
        ChBind::Bool(b) => query.bind(*b),
        ChBind::Str(s) => query.bind(s.clone()),
    }
}

/// Run a statement against a (cheap-cloned) `Client`, binding `bound` to the
/// `?` placeholders, fetching `JSONEachRow` bytes, and marshalling them to
/// capped JSON rows.
///
/// A `read_only` statement runs over HTTP GET (which ClickHouse treats as
/// read-only server-side, in addition to the register-time keyword guard); a
/// write statement runs over POST and returns no rows.
/// `max_execution_time` is the server-side budget (seconds, rounded up); the
/// outer tokio timeout in `lib.rs` is the hard ceiling.
pub async fn run_query(
    client: &Client,
    statement: &str,
    bound: Vec<ChBind>,
    max_rows: usize,
    read_only: bool,
    timeout: Duration,
) -> Result<QueryOutcome, String> {
    run_query_with_settings(client, statement, bound, max_rows, read_only, timeout, &[]).await
}

/// Like [`run_query`] but also applies operator-fixed query `settings` via the
/// driver's `.with_option(k, v)`. The settings come from operator config only
/// (never caller args). They are applied AFTER the `max_execution_time`
/// default, so an explicit operator entry (e.g. a tighter `max_execution_time`)
/// overrides the default for that key.
pub async fn run_query_with_settings(
    client: &Client,
    statement: &str,
    bound: Vec<ChBind>,
    max_rows: usize,
    read_only: bool,
    timeout: Duration,
    settings: &[(String, String)],
) -> Result<QueryOutcome, String> {
    let mut query = client.query(statement);
    for b in &bound {
        query = bind_value(query, b);
    }

    // Server-side execution budget — at least 1s when a sub-second timeout is
    // configured, so ClickHouse does not see `max_execution_time=0` (unbounded).
    let secs = timeout.as_secs().max(1);
    query = query.with_option("max_execution_time", secs.to_string());
    // A read profile's statement is keyword-guarded at register time and goes
    // out over HTTP GET, which ClickHouse already treats as read-only at the
    // server. Sending an explicit `readonly` setting on top of that is rejected
    // ("cannot modify 'readonly' setting in readonly mode"), so the server-side
    // read-only guard rides on the GET method rather than a settings override.
    // Operator-fixed settings last so they win over the defaults above.
    for (k, v) in settings {
        query = query.with_option(k, v);
    }

    // A write profile statement (DDL / INSERT) returns no rows and must go out
    // over HTTP POST — ClickHouse treats a GET as implicitly `readonly` and
    // rejects any modifying query. The driver's `fetch_*` path forces GET for
    // short queries, so writes run through `execute()` (POST) and yield an
    // empty result set; reads keep the `fetch_bytes` JSONEachRow path.
    if !read_only {
        query
            .execute()
            .await
            .map_err(|e| format!("ClickHouse query failed: {e}"))?;
        return Ok(QueryOutcome {
            rows: Vec::new(),
            truncated: false,
            row_count: 0,
        });
    }

    let cursor = query
        .fetch_bytes("JSONEachRow")
        .map_err(|e| format!("ClickHouse query failed: {e}"))?;
    let bytes = collect_cursor(cursor).await?;
    parse_json_each_row(&bytes, max_rows)
}

/// Collect all response bytes from a [`clickhouse::query::BytesCursor`].
async fn collect_cursor(mut cursor: clickhouse::query::BytesCursor) -> Result<Vec<u8>, String> {
    let bytes = cursor
        .collect()
        .await
        .map_err(|e| format!("ClickHouse response read failed: {e}"))?;
    Ok(bytes.to_vec())
}

/// Parse a `JSONEachRow` (NDJSON) response body into capped JSON rows. Each
/// non-empty line is one JSON object. The cap is on materialised rows; the
/// `row_count` reflects the exact number of rows the server returned, and
/// `truncated` is set when rows beyond the cap existed. A non-object line is an
/// error (the marshaller only emits object rows, mirroring the SQL backends).
pub fn parse_json_each_row(bytes: &[u8], max_rows: usize) -> Result<QueryOutcome, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| format!("ClickHouse response is not valid UTF-8: {e}"))?;

    let mut out = Vec::new();
    let mut truncated = false;
    let mut row_count = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|e| format!("ClickHouse JSONEachRow parse failed: {e}"))?;
        if !value.is_object() {
            return Err(format!(
                "ClickHouse JSONEachRow row is not a JSON object: {line}"
            ));
        }
        row_count += 1;
        if out.len() >= max_rows {
            truncated = true;
            continue;
        }
        out.push(value);
    }

    Ok(QueryOutcome {
        rows: out,
        truncated,
        row_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_only_guard_allows_reads() {
        for s in [
            "SELECT 1",
            "  with x as (select 1) select * from x",
            "-- comment\nSELECT 2",
            "/* hi */ EXPLAIN SELECT 1",
            "SHOW TABLES",
            "DESCRIBE TABLE t",
        ] {
            assert!(enforce_read_only(s).is_ok(), "should allow: {s}");
        }
    }

    #[test]
    fn read_only_guard_rejects_writes_and_ddl() {
        for s in [
            "INSERT INTO t VALUES (1)",
            "ALTER TABLE t UPDATE x = 1 WHERE 1",
            "CREATE TABLE t(x Int32) ENGINE = Memory",
            "DROP TABLE t",
            "TRUNCATE TABLE t",
            "   ",
            "",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
    }

    /// The local guard must keep delegating to the shared hardened helper:
    /// a regression that re-introduces a first-keyword-only check would let
    /// these through and fail here.
    #[test]
    fn read_only_guard_delegates_to_hardened_helper() {
        assert!(enforce_read_only("SELECT 1").is_ok());
        // data-modifying CTE: leading WITH passes the old check but writes.
        assert!(enforce_read_only("WITH x AS (INSERT INTO t SELECT 1) SELECT * FROM x").is_err());
        // EXPLAIN ANALYZE executes its inner statement.
        assert!(enforce_read_only("EXPLAIN ANALYZE SELECT 1").is_err());
        // stacked statements.
        assert!(enforce_read_only("SELECT 1; DROP TABLE t").is_err());
    }

    #[test]
    fn parses_json_each_row_objects() {
        let body = b"{\"id\":1,\"name\":\"alice\"}\n{\"id\":2,\"name\":\"bob\"}\n";
        let oc = parse_json_each_row(body, 1_000).expect("parse");
        assert_eq!(oc.row_count, 2);
        assert!(!oc.truncated);
        assert_eq!(oc.rows[0], json!({ "id": 1, "name": "alice" }));
        assert_eq!(oc.rows[1], json!({ "id": 2, "name": "bob" }));
    }

    #[test]
    fn parses_empty_body_as_zero_rows() {
        let oc = parse_json_each_row(b"", 1_000).expect("parse");
        assert_eq!(oc.row_count, 0);
        assert!(oc.rows.is_empty());
        assert!(!oc.truncated);
    }

    #[test]
    fn skips_blank_lines() {
        let body = b"{\"a\":1}\n\n  \n{\"a\":2}\n";
        let oc = parse_json_each_row(body, 1_000).expect("parse");
        assert_eq!(oc.row_count, 2);
    }

    #[test]
    fn max_rows_cap_sets_truncated_and_exact_count() {
        let body = b"{\"n\":0}\n{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n{\"n\":4}\n";
        let oc = parse_json_each_row(body, 3).expect("parse");
        assert_eq!(oc.rows.len(), 3);
        assert!(oc.truncated);
        assert_eq!(oc.row_count, 5);
    }

    #[test]
    fn non_object_row_is_rejected() {
        let body = b"42\n";
        assert!(parse_json_each_row(body, 10).is_err());
    }

    #[test]
    fn malformed_json_is_rejected() {
        let body = b"{not json}\n";
        assert!(parse_json_each_row(body, 10).is_err());
    }

    /// The client builds without opening a socket — `register_profile` stays
    /// offline. Building it must not panic or block.
    #[test]
    fn client_builds_without_connecting() {
        let _c = build_client(
            "http://localhost:8123",
            Some("analytics"),
            Some("reader"),
            Some("pw"),
        );
        // No assertion on internals — the point is that construction is I/O-free
        // and returns synchronously without a runtime.
    }

    #[test]
    fn client_builds_with_minimal_args() {
        let _c = build_client("https://localhost:8443", None, None, None);
    }

    #[test]
    fn list_tables_query_binds_database_filter_as_param() {
        let q = build_list_tables_query(Some("analytics"), 500);
        // The filter is a bound `?`, never interpolated into the SQL text.
        assert!(q.sql.contains("FROM system.tables"));
        assert!(q.sql.contains("WHERE database = ?"));
        assert!(
            !q.sql.contains("analytics"),
            "filter must not be interpolated: {}",
            q.sql
        );
        assert!(q.sql.ends_with("LIMIT ?"));
        assert_eq!(
            q.binds,
            vec![ChBind::Str("analytics".to_owned()), ChBind::Int(500)]
        );
    }

    #[test]
    fn list_tables_query_without_filter_lists_all_databases() {
        let q = build_list_tables_query(None, 100);
        assert!(!q.sql.contains("WHERE"), "{}", q.sql);
        // Only the LIMIT bind remains.
        assert_eq!(q.binds, vec![ChBind::Int(100)]);
        // Whitespace-only filters collapse to "no filter".
        let q2 = build_list_tables_query(Some("   "), 100);
        assert_eq!(q2.binds, vec![ChBind::Int(100)]);
    }

    #[test]
    fn list_columns_query_binds_table_and_database_as_params() {
        let q = build_list_columns_query(Some("analytics"), Some("events"), 1000);
        assert!(q.sql.contains("FROM system.columns"));
        assert!(q.sql.contains("WHERE database = ? AND table = ?"));
        assert!(
            !q.sql.contains("analytics") && !q.sql.contains("events"),
            "filters must not be interpolated: {}",
            q.sql
        );
        assert!(q.sql.ends_with("LIMIT ?"));
        assert_eq!(
            q.binds,
            vec![
                ChBind::Str("analytics".to_owned()),
                ChBind::Str("events".to_owned()),
                ChBind::Int(1000),
            ]
        );
    }

    #[test]
    fn list_columns_query_table_only_filter() {
        let q = build_list_columns_query(None, Some("events"), 50);
        assert!(q.sql.contains("WHERE table = ?"));
        assert!(!q.sql.contains("database = ?"), "{}", q.sql);
        assert_eq!(
            q.binds,
            vec![ChBind::Str("events".to_owned()), ChBind::Int(50)]
        );
    }

    /// Marshalling a fabricated `system.tables` JSONEachRow body produces typed
    /// catalog rows via the shared row→JSON path.
    #[test]
    fn marshals_fabricated_list_tables_rows() {
        let body = b"{\"database\":\"analytics\",\"name\":\"events\",\"engine\":\"MergeTree\",\"total_rows\":1000,\"total_bytes\":4096}\n";
        let oc = parse_json_each_row(body, 1_000).expect("parse");
        assert_eq!(oc.row_count, 1);
        assert_eq!(oc.rows[0]["database"], json!("analytics"));
        assert_eq!(oc.rows[0]["name"], json!("events"));
        assert_eq!(oc.rows[0]["engine"], json!("MergeTree"));
        assert_eq!(oc.rows[0]["total_rows"], json!(1000));
    }

    /// Marshalling a fabricated `system.columns` JSONEachRow body.
    #[test]
    fn marshals_fabricated_list_columns_rows() {
        let body = b"{\"database\":\"analytics\",\"table\":\"events\",\"name\":\"ts\",\"type\":\"DateTime\",\"position\":1,\"default_kind\":\"\"}\n";
        let oc = parse_json_each_row(body, 1_000).expect("parse");
        assert_eq!(oc.rows[0]["table"], json!("events"));
        assert_eq!(oc.rows[0]["name"], json!("ts"));
        assert_eq!(oc.rows[0]["type"], json!("DateTime"));
        assert_eq!(oc.rows[0]["position"], json!(1));
    }

    /// Operator settings build without panic (the `.with_option` application is
    /// I/O-free; the socket only opens on fetch). This exercises the
    /// settings-application code path against a non-connecting client.
    #[tokio::test]
    async fn run_query_with_settings_applies_options_offline() {
        let client = build_client("http://127.0.0.1:1", None, None, None);
        let settings = vec![
            ("max_threads".to_owned(), "2".to_owned()),
            ("readonly".to_owned(), "1".to_owned()),
        ];
        // No server is listening on 127.0.0.1:1, so the fetch fails fast — but
        // building the query + applying every setting must not panic, proving the
        // settings-application path is exercised.
        let out = run_query_with_settings(
            &client,
            "SELECT 1",
            Vec::new(),
            10,
            true,
            Duration::from_millis(50),
            &settings,
        )
        .await;
        assert!(
            out.is_err(),
            "expected a transport error against a dead port"
        );
    }
}
