//! ClickHouse structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is the
//! gateway's `is_error` signal (same contract as the duckdb/snowflake/http
//! backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn clickhouse_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_clickhouse.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_server_and_retry" } else { "inspect_sql_error" },
    })
}

/// Classify a query error string. Transient network / timeout / overload
/// failures are retryable transport errors; parser / type / unknown-column /
/// permission rejections are caller/config problems and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    // Non-retryable first: a syntax/type/permission error must not be masked as
    // transport just because its text happens to mention "connection".
    let non_retryable = lower.contains("syntax error")
        || lower.contains("syntax_error")
        || lower.contains("unknown identifier")
        || lower.contains("unknown column")
        || lower.contains("unknown table")
        || lower.contains("unknown database")
        || lower.contains("type mismatch")
        || lower.contains("cannot parse")
        || lower.contains("illegal type")
        || lower.contains("not enough privileges")
        || lower.contains("access_denied")
        || lower.contains("access denied")
        || lower.contains("readonly")
        || lower.contains("read-only")
        || lower.contains("cannot_modify");
    let retryable = !non_retryable
        && (lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("connection")
            || lower.contains("network")
            || lower.contains("connect")
            || lower.contains("too many simultaneous")
            || lower.contains("memory limit")
            || lower.contains("socket")
            || lower.contains("temporarily")
            || lower.contains("service unavailable")
            || lower.contains("503")
            || lower.contains("502"));
    let kind = if retryable {
        "transport_error"
    } else {
        "clickhouse_error"
    };
    clickhouse_downstream_error(kind, message, retryable)
}

/// JSON Schema (draft 2020-12) for the fixed envelope wrapper
/// [`build_result_envelope`] produces. Describes the stable top-level shape;
/// per-query `response.rows` items are intentionally left untyped (`{}`) so any
/// row shape validates.
pub fn result_envelope_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "toolName": { "type": "string" },
            "profile": { "type": "string" },
            "request": {
                "type": "object",
                "properties": {
                    "database": { "type": "string" }
                },
                "additionalProperties": true
            },
            "response": {
                "type": ["object", "null"],
                "properties": {
                    "rows": { "type": ["array", "null"], "items": {} },
                    "count": { "type": ["integer", "null"] },
                    "truncated": { "type": "boolean" },
                    "durationMs": { "type": "integer" }
                },
                "additionalProperties": true
            },
            "downstreamError": { "type": ["object", "null"] },
            "downstreamErrors": { "type": "array", "items": {} },
            "error": { "type": ["string", "null"] }
        },
        "additionalProperties": true
    })
}

/// Envelope schema specialized for a catalog-introspection operation: the same
/// wrapper as [`result_envelope_schema`] but with `response.rows` items typed to
/// the known `system.tables` / `system.columns` column set. The object stays
/// open (`additionalProperties: true`) so a future ClickHouse column still
/// validates. `columns` are the projected column names; their values keep the
/// JSON shape the `JSONEachRow` marshaller produces (so they are left untyped).
pub fn catalog_envelope_schema(columns: &[&str]) -> Value {
    let mut schema = result_envelope_schema();
    let mut props = serde_json::Map::new();
    for col in columns {
        // Catalog cell values keep their native JSON type (string / int / null).
        props.insert((*col).to_owned(), json!({}));
    }
    schema["properties"]["response"]["properties"]["rows"]["items"] = json!({
        "type": "object",
        "properties": Value::Object(props),
        "additionalProperties": true,
    });
    schema
}

/// Build the ClickHouse structured-content envelope returned as the
/// `BackendResponse.payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    database: &str,
    rows: Option<&[Value]>,
    row_count: Option<usize>,
    truncated: bool,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = if downstream_error.is_some() {
        Value::Null
    } else {
        json!({
            "rows": rows,
            "count": row_count.or_else(|| rows.map(<[Value]>::len)),
            "truncated": truncated,
            "durationMs": duration_ms,
        })
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "database": database,
        },
        "response": response,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_retryable_transport_error() {
        let e = classify_error("ClickHouse query failed: connection timed out");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn network_failure_is_retryable() {
        let e = classify_error("Network error: connection refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn syntax_error_is_not_retryable() {
        let e = classify_error("Code: 62. DB::Exception: Syntax error: failed at position 1");
        assert_eq!(e["kind"], json!("clickhouse_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn readonly_denial_is_not_retryable() {
        let e = classify_error("Cannot execute query in readonly mode");
        assert_eq!(e["kind"], json!("clickhouse_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn query_envelope_has_rows_and_count() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "default",
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["rows"][0]["id"], json!(1));
        assert_eq!(env["response"]["truncated"], json!(false));
        assert_eq!(env["request"]["database"], json!("default"));
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn truncated_flag_is_carried() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "default",
            Some(&rows),
            Some(1),
            true,
            3,
            None,
            None,
        );
        assert_eq!(env["response"]["truncated"], json!(true));
    }

    #[test]
    fn error_envelope_nulls_response() {
        let d = classify_error("Code: 60. DB::Exception: Unknown table default.bogus");
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "default",
            None,
            None,
            false,
            2,
            Some(&d),
            Some("table missing"),
        );
        assert!(env["response"].is_null());
        assert_eq!(env["downstreamError"]["kind"], json!("clickhouse_error"));
    }

    #[test]
    fn catalog_envelope_schema_types_known_columns() {
        let schema = catalog_envelope_schema(crate::engine::LIST_TABLES_COLUMNS);
        let item = &schema["properties"]["response"]["properties"]["rows"]["items"];
        assert_eq!(item["type"], json!("object"));
        assert!(item["properties"]["database"].is_object());
        assert!(item["properties"]["name"].is_object());
        assert!(item["properties"]["engine"].is_object());
        assert_eq!(item["additionalProperties"], json!(true));
    }

    #[test]
    fn output_schema_matches_envelope_shape() {
        let schema = result_envelope_schema();
        assert_eq!(schema["type"], json!("object"));
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "default",
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        let props = schema["properties"].as_object().expect("properties object");
        for key in env.as_object().expect("envelope object").keys() {
            assert!(props.contains_key(key), "schema missing key `{key}`");
        }
        assert_eq!(
            schema["properties"]["response"]["properties"]["rows"]["items"],
            json!({})
        );
    }
}
