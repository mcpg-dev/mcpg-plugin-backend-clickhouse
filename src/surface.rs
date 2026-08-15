//! MCP surface shaping for resource / prompt bindings.
//!
//! A binding is a tool by default; the operator may instead place it under
//! `mcp.capabilities.resources[]` / `resource_templates[]` / `prompts[]`. The
//! gateway routes those reads to the same `execute()` path but applies a strict
//! decoder over the response body — `{contents:[…]}` for `resources/read` and
//! `{messages:[…]}` for `prompts/get`. The tool surface keeps the raw envelope.
//!
//! On the resource surface the requested URI arrives in the call arguments as a
//! top-level `uri` field (the gateway materializes it from the resource read
//! request); an operator may also pin a static `uri` on the binding. The prompt
//! surface carries no URI.

use mcpg_plugin_protocol::{ListedResource, ResourcePage};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::types::{ListQueryConfig, ListQueryMode};

/// Project list_query result rows into a [`ResourcePage`].
///
/// Reads `uri` (required) plus optional `name` / `description` / `mime_type`
/// columns. The next-cursor derives from the last row's `cursor_column` value
/// in keyset mode, or `prior_offset + rows` in offset mode. A page shorter than
/// `page_size` exhausts the listing (`next_cursor == None`). Rows missing `uri`
/// are skipped — a misconfigured listing never poisons the whole surface.
pub fn rows_to_resource_page(
    rows: &[Value],
    cfg: &ListQueryConfig,
    prior_offset: u64,
) -> ResourcePage {
    let row_count = rows.len() as u64;
    let mut resources: Vec<ListedResource> = Vec::with_capacity(rows.len());
    let mut last_cursor_value: Option<String> = None;

    for row in rows {
        let Value::Object(obj) = row else { continue };
        let Some(uri) = obj.get("uri").and_then(Value::as_str) else {
            continue;
        };
        resources.push(ListedResource {
            uri: uri.to_owned(),
            name: obj.get("name").and_then(Value::as_str).map(str::to_owned),
            description: obj
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned),
            mime_type: obj
                .get("mime_type")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
        if let Some(col) = cfg.cursor_column.as_deref()
            && let Some(v) = obj.get(col)
        {
            last_cursor_value = Some(cursor_value_to_string(v));
        }
    }

    let next_cursor = if row_count < cfg.page_size {
        None
    } else {
        match cfg.mode {
            ListQueryMode::Keyset => last_cursor_value,
            ListQueryMode::Offset => Some((prior_offset + row_count).to_string()),
        }
    };

    ResourcePage {
        resources,
        next_cursor,
    }
}

/// Render a JSON cursor value to its opaque string form (ids / timestamps /
/// UUIDs round-trip stably).
fn cursor_value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Extract completion candidates from a query result: the first column of each
/// row, coerced to a string, capped at `max`. Non-string cells are skipped.
pub fn rows_to_completion_values(
    rows: &[Value],
    first_column: Option<&str>,
    max: usize,
) -> Vec<String> {
    let mut out = Vec::with_capacity(rows.len().min(max));
    for row in rows.iter().take(max) {
        let cell = match (first_column, row) {
            (Some(col), Value::Object(map)) => map.get(col),
            _ => None,
        };
        if let Some(Value::String(s)) = cell {
            out.push(s.clone());
        }
    }
    out
}

/// Which MCP surface a binding serves. `Tool` (default) keeps the historical
/// tool-shaped envelope byte-for-byte; `Resource` / `Prompt` reshape successful
/// rows into the surface-correct body the gateway decoder requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Tool surface — unchanged envelope.
    #[default]
    Tool,
    /// `resources/read` surface — `{contents:[{uri,text,mimeType}]}`.
    Resource,
    /// `prompts/get` surface — `{messages:[{role,content}]}`.
    Prompt,
}

impl Surface {
    /// Stable label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Tool => "tool",
            Surface::Resource => "resource",
            Surface::Prompt => "prompt",
        }
    }
}

/// Resolve the resource URI for a `resources/read`: a static binding `uri`
/// wins, otherwise the gateway-supplied `uri` argument. Returns `None` when
/// neither is available so the caller can surface a clean error envelope
/// instead of emitting a decoder-invalid `{contents}` body.
pub fn resolve_resource_uri<'a>(
    static_uri: Option<&'a str>,
    arguments: &'a Value,
) -> Option<&'a str> {
    if let Some(u) = static_uri
        && !u.trim().is_empty()
    {
        return Some(u);
    }
    arguments
        .get("uri")
        .and_then(Value::as_str)
        .filter(|u| !u.trim().is_empty())
}

/// Wrap successful result rows into the `resources/read` contract body —
/// `{contents:[{uri, text, mimeType:"application/json"}]}` — a single content
/// entry whose `text` is the JSON array of rows.
pub fn resource_contents_body(uri: &str, rows: &[Value]) -> Value {
    let text = serde_json::to_string(rows).unwrap_or_else(|_| "[]".to_owned());
    json!({
        "contents": [
            {
                "uri": uri,
                "text": text,
                "mimeType": "application/json",
            }
        ]
    })
}

/// Wrap successful result rows into the `prompts/get` contract body —
/// `{messages:[{role:"user", content:{type:"text", text:<rows-as-json>}}]}`.
pub fn prompt_messages_body(rows: &[Value]) -> Value {
    let text = serde_json::to_string(rows).unwrap_or_else(|_| "[]".to_owned());
    json!({
        "messages": [
            {
                "role": "user",
                "content": { "type": "text", "text": text }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_default_is_tool() {
        assert_eq!(Surface::default(), Surface::Tool);
    }

    #[test]
    fn surface_parses_snake_case() {
        let s: Surface = serde_json::from_value(json!("resource")).unwrap();
        assert_eq!(s, Surface::Resource);
        let s: Surface = serde_json::from_value(json!("prompt")).unwrap();
        assert_eq!(s, Surface::Prompt);
    }

    #[test]
    fn static_uri_wins_over_argument() {
        let args = json!({ "uri": "clickhouse://from-arg" });
        assert_eq!(
            resolve_resource_uri(Some("clickhouse://static"), &args),
            Some("clickhouse://static")
        );
    }

    #[test]
    fn falls_back_to_argument_uri() {
        let args = json!({ "uri": "clickhouse://docs/readme" });
        assert_eq!(
            resolve_resource_uri(None, &args),
            Some("clickhouse://docs/readme")
        );
    }

    #[test]
    fn no_uri_available_returns_none() {
        assert_eq!(resolve_resource_uri(None, &json!({})), None);
        assert_eq!(resolve_resource_uri(Some("  "), &json!({})), None);
    }

    #[test]
    fn resource_body_satisfies_decoder_shape() {
        let rows = vec![json!({ "id": 1 }), json!({ "id": 2 })];
        let body = resource_contents_body("clickhouse://docs", &rows);
        let contents = body["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!("clickhouse://docs"));
        assert!(contents[0]["text"].is_string());
        assert!(contents[0].get("blob").is_none());
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let decoded: Vec<Value> =
            serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, rows);
    }

    fn keyset_cfg(page_size: u64) -> ListQueryConfig {
        ListQueryConfig {
            sql: "SELECT id AS uri FROM t".into(),
            mode: ListQueryMode::Keyset,
            cursor_column: Some("id".into()),
            page_size,
        }
    }

    #[test]
    fn rows_map_to_resources_with_optional_columns() {
        let rows = vec![
            json!({ "uri": "clickhouse://a", "name": "A", "description": "first", "mime_type": "text/plain", "id": 1 }),
            json!({ "uri": "clickhouse://b", "id": 2 }),
        ];
        let page = rows_to_resource_page(&rows, &keyset_cfg(10), 0);
        assert_eq!(page.resources.len(), 2);
        assert_eq!(page.resources[0].uri, "clickhouse://a");
        assert_eq!(page.resources[0].name.as_deref(), Some("A"));
        assert_eq!(page.resources[0].description.as_deref(), Some("first"));
        assert_eq!(page.resources[0].mime_type.as_deref(), Some("text/plain"));
        assert!(page.resources[1].name.is_none());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn full_keyset_page_carries_cursor() {
        let rows = vec![json!({ "uri": "clickhouse://a", "id": 7 })];
        let page = rows_to_resource_page(&rows, &keyset_cfg(1), 0);
        assert_eq!(page.next_cursor.as_deref(), Some("7"));
    }

    #[test]
    fn offset_full_page_advances_offset() {
        let cfg = ListQueryConfig {
            sql: "SELECT id AS uri FROM t LIMIT ? OFFSET ?".into(),
            mode: ListQueryMode::Offset,
            cursor_column: None,
            page_size: 2,
        };
        let rows = vec![
            json!({ "uri": "clickhouse://a" }),
            json!({ "uri": "clickhouse://b" }),
        ];
        let page = rows_to_resource_page(&rows, &cfg, 4);
        assert_eq!(page.next_cursor.as_deref(), Some("6"));
    }

    #[test]
    fn rows_without_uri_are_skipped() {
        let rows = vec![
            json!({ "name": "no uri" }),
            json!({ "uri": "clickhouse://ok" }),
        ];
        let page = rows_to_resource_page(&rows, &keyset_cfg(10), 0);
        assert_eq!(page.resources.len(), 1);
        assert_eq!(page.resources[0].uri, "clickhouse://ok");
    }

    #[test]
    fn completion_values_take_first_column_and_cap() {
        let rows = vec![
            json!({ "name": "alpha" }),
            json!({ "name": "alphabet" }),
            json!({ "name": 99 }),
        ];
        let got = rows_to_completion_values(&rows, Some("name"), 10);
        assert_eq!(got, vec!["alpha".to_owned(), "alphabet".to_owned()]);
        let capped = rows_to_completion_values(&rows, Some("name"), 1);
        assert_eq!(capped, vec!["alpha".to_owned()]);
    }

    #[test]
    fn prompt_body_satisfies_decoder_shape() {
        let rows = vec![json!({ "answer": 42 })];
        let body = prompt_messages_body(&rows);
        let messages = body["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        assert!(messages[0]["content"]["text"].is_string());
    }
}
