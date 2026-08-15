# ClickHouse Binding (`dev.mcpg.backend.clickhouse`)

A **backend (binding)** plugin that runs an operator-fixed analytical SQL
statement against a ClickHouse server (OSS, Cloud, Altinity) over its HTTP
interface and returns rows as JSON. Each binding declares **one statement**
against an operator-configured `url` + credentials, and that binding becomes one
MCP tool (or resource / prompt) — the `sql`/`duckdb`/`snowflake` envelope model.
Dispatches over the official `clickhouse` driver (async, hyper transport,
rustls — no native-tls / OpenSSL).

## How a binding runs

- The statement uses `?` **positional placeholders** bound from `params` — an
  ordered list of CEL expressions evaluated against the tool arguments
  (`arguments.*`). Each value is escaped + serialized by the driver as a
  ClickHouse SQL literal (strings single-quote-escaped), so caller input can
  **never alter the statement** (injection-safe). `params[i]` → the i-th `?`. A
  literal `?` in the statement is written `??`.
- Only scalar binds are allowed (string / int / float / bool / null); arrays and
  objects are rejected at call time (a single `?` can't carry them).
- Each call runs `query(statement).bind(..).fetch_bytes("JSONEachRow")`, collects
  the response, and parses the NDJSON stream (one JSON object per line) into
  capped JSON rows.

## Binding config (`backend: { kind: clickhouse, ... }`)

| Field | Type | Default | Description |
|---|---|---|---|
| `operation` | enum | `query` | `query` \| `list_tables` \| `list_columns`. `query` runs `statement`; the catalog operations perform read-only schema discovery (see below). |
| `url` | string | *(required)* | ClickHouse HTTP endpoint (`https://host:8443` for Cloud, `http://host:8123` for OSS). Operator-configured, never caller-templated → no SSRF on the URL. |
| `database` | string | `default` | Target database. |
| `catalog_database` | string | *(none)* | Static database-name filter for the catalog operations, bound as `WHERE database = ?` (never interpolated). Omitted → all databases. |
| `catalog_database_arg` | string | *(none)* | Per-call argument name overriding `catalog_database` (bound, narrows only). |
| `catalog_table` | string | *(none)* | Static table-name filter for `list_columns`, bound as `WHERE table = ?`. Required (or `catalog_table_arg`) for `list_columns`. |
| `catalog_table_arg` | string | *(none)* | Per-call argument name overriding `catalog_table` (bound, narrows only). |
| `auth.username` | string | `default` (server default) | ClickHouse user. |
| `auth.password` | string | *(none)* | HTTP-basic password, resolved from a config-origin `${cred://…}` / `${env.X}` reference. |
| `tls.verify_peer` | bool | `true` | Verify the server TLS certificate chain + hostname. **`false` is rejected at register** — see below. |
| `statement` | string | *(required for `query`)* | The operator-fixed statement; `?` placeholders bound from `params`. Ignored (may be omitted) for the catalog operations. |
| `params` | string[] | `[]` | Ordered CEL expressions; `params[i]` → the i-th `?`. Ignored for the catalog operations. |
| `query.max_execution_time_ms` | int | `30000` | Per-call ceiling, applied both as the outer tokio timeout AND the server-side `max_execution_time` (seconds, rounded up). |
| `query.max_result_rows` | int | `100000` | Client-side row cap; extra rows set the envelope `truncated` flag. Also the catalog `LIMIT`. |
| `query.read_only` | bool | `true` | Read-only guard (see below). Catalog operations are always read-only regardless. |
| `query.settings` | map | `{}` | Operator-fixed per-query ClickHouse settings applied via the driver's `.with_option(k, v)` (see below). |
| `surface` | enum | `tool` | `tool` \| `resource` \| `prompt` — the MCP surface this binding serves. |
| `uri` | string | *(none)* | Static resource URI for `surface: resource` (else the requested URI is used). |
| `list_query` | object | *(none)* | Operator-fixed listing statement for `resources/list` (keyset / offset pagination). |
| `variable_completions` | map | `{}` | Per-template-variable completion query for `completion/complete`; the single `?` is bound to the typed prefix. |

### Read-only guard

When `query.read_only` is `true` (the default):

- The operator-fixed `statement` (and any `list_query` / `variable_completions`
  SQL) must begin with a read-only keyword (`SELECT` / `WITH` / `SHOW` /
  `DESCRIBE` / `EXPLAIN`) — checked at register (leading whitespace + `--` / `/* */`
  comments are stripped first; fail-closed on an empty/unparseable statement).
- The server-side `readonly=1` setting is applied per query — ClickHouse itself
  refuses any write / settings-changing statement.

Set `query.read_only: false` to allow writes (operator responsibility).

### TLS

TLS always verifies the server certificate (the driver's default rustls
connector, webpki roots). **There is no certificate-verification opt-out.** A
binding that sets `tls.verify_peer: false` is rejected at `register_profile`
with a clear error — configure a trusted CA instead. The `verify_peer` field is
retained in the spec (default `true`) for forward compatibility.

> **Deferred capability:** an insecure no-verify TLS path
> (`tls.verify_peer: false`) for self-signed dev servers is intentionally **not
> supported**. Earlier drafts built a custom hyper client through the
> `clickhouse` crate's unstable, by-convention-private `_priv` module; that
> dependency is removed to keep TLS secure-by-default and the build robust. If a
> no-verify path is ever needed it must be reintroduced through a stable driver
> API.

### Secret references

The auth password is never a config literal — it rides a config-origin secret
reference:

- `${env.X}` — resolved at config load (bare `${env.…}` dot form).
- `${cred://<plugin-id>/<target>}` — resolved per caller.

A bare `cred://` left inside an operator-fixed string (`url` / `statement`) is
rejected at register (it would otherwise be sent to ClickHouse verbatim). The
resolved secret is never logged and never reflected into the response envelope.

## Example

```yaml
# 1. Load the backend plugin artifact (top-level `plugins:` is a flat list).
plugins:
  - id: dev.mcpg.backend.clickhouse
    class: backend
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/backend-clickhouse:protocol-1" }

# 2. Declare each binding as a tool under `mcp.capabilities.tools[]`.
#    Each entry's `backend.kind: clickhouse` routes to the plugin above.
mcp:
  capabilities:
    tools:
      - name: events.by_user
        description: Recent events for a user.
        annotations: { read_only: true, open_world: false }
        backend:
          kind: clickhouse
          url: "https://ch.internal:8443"
          database: analytics
          auth:
            username: reader
            password: "${cred://ch-creds/reader}"
          statement: "SELECT event, ts FROM events WHERE user_id = ? ORDER BY ts DESC LIMIT 100"
          params: ["arguments.user_id"]
```

## Schema discovery (catalog introspection)

Instead of running a fixed `statement`, a binding can perform **read-only schema
discovery** by setting `operation`:

- **`list_tables`** → `SELECT database, name, engine, total_rows, total_bytes
  FROM system.tables [WHERE database = ?] ORDER BY database, name LIMIT ?`.
- **`list_columns`** → `SELECT database, table, name, type, position,
  default_kind FROM system.columns [WHERE database = ? AND table = ?] ORDER BY
  database, table, position LIMIT ?`. A table filter is **required** (static
  `catalog_table` or per-call `catalog_table_arg`) — otherwise it would list
  every column of every table.

The optional filters are passed as **bound query parameters** (the same
`Query::bind` server-side path the `query` op uses) — **never** string-
interpolated — so caller input can only *narrow* the metadata, never alter the
catalog query. The catalog operations ignore `statement` / `params`, are
inherently read-only (the server-side `readonly=1` is forced on regardless of
`query.read_only`), and emit the standard result envelope with `response.rows`
typed to the projected column set. The configured `*_arg` names surface as the
tool's `input_schema` properties. The `LIMIT` is `query.max_result_rows`.

```yaml
# List the tables in one database.
- name: schema.tables
  backend:
    kind: clickhouse
    url: "https://ch.internal:8443"
    operation: list_tables
    catalog_database: analytics

# List a table's columns; the caller may pick the table via the `table` argument.
- name: schema.columns
  backend:
    kind: clickhouse
    url: "https://ch.internal:8443"
    operation: list_columns
    catalog_database: analytics
    catalog_table_arg: table        # caller-narrowed (bound, never interpolated)
```

## Query settings (passthrough)

`query.settings` applies operator-fixed ClickHouse settings on **every** query
via the driver's `.with_option(key, value)`. They are **operator-config only**
(never caller-supplied), so a caller can never widen a setting. Settings are
applied *after* the read-only `readonly=1` / `max_execution_time` defaults, so an
explicit entry overrides the default for that key.

The intended guardrail settings are `readonly` (`1` = no writes, `2` = no
writes + no settings changes) and the `max_*` family (`max_execution_time`,
`max_threads`, `max_memory_usage`, `max_result_rows`, …).

```yaml
backend:
  kind: clickhouse
  url: "https://ch.internal:8443"
  statement: "SELECT event, ts FROM events WHERE user_id = ? LIMIT 100"
  params: ["arguments.user_id"]
  query:
    settings:
      readonly: "1"
      max_threads: "4"
      max_memory_usage: "2000000000"
```

## MCP surfaces

The same binding works on every MCP surface; the surface is selected by the
capability list the binding sits under plus the `surface:` knob.

- **Tool** (default): the unchanged result envelope (`{ response: { rows, count,
  truncated, durationMs }, downstreamError, … }`).
- **Resource** (`surface: resource`, under `resources[]`): rows reshaped into the
  `resources/read` `{contents:[{uri, text, mimeType}]}` body. `list_query`
  enumerates resources for `resources/list`; `variable_completions` feeds
  `completion/complete` (the single `?` is **bound** to the typed prefix —
  injection-safe).
- **Prompt** (`surface: prompt`, under `prompts[]`): rows reshaped into the
  `prompts/get` `{messages:[…]}` body.

## Change-watching

A resource can subscribe to ClickHouse changes through the plugin's second
entity — a **polling `watch_strategy`** (kind `clickhouse_poll`). ClickHouse has
no native change-push channel, so the strategy runs a cheap read-only scalar
**high-water query** (`tracking_query`) on a cadence and emits
`notifications/resources/updated` whenever that scalar advances. The first tick
only records a baseline, so a watcher never fires spuriously at startup.

Attach it under a resource's `watch:` block. The watch carries its own
connection (it is not tied to the binding's profile) plus the tracking query:

```yaml
mcp.configurations[].resources[].watch:
  type: plugin
  kind: clickhouse_poll
  url: "https://ch.internal:8443"
  auth: { ... }
  tracking_query: "SELECT max(event_time) FROM events"
  interval_ms: 30000
```

**Watch spec fields**

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | *(required)* | ClickHouse HTTP endpoint. Operator-fixed. |
| `database` | string | `default` | Target database. |
| `auth` | object | *(none)* | HTTP-basic `username` + config-resolved `password` (same shape as the binding). |
| `tls.verify_peer` | bool | `true` | `false` is rejected at watch start (no no-verify path). |
| `tracking_query` | string | *(required)* | Read-only scalar high-water query; its first-row first-column value is the cursor. |
| `interval_ms` | int | `60000` | Poll cadence (floored at 250 ms). |
| `timeout_ms` | int | `10000` | Per-tick query budget (server-side + wall-clock). |

The `tracking_query` is held to the same read-only keyword guard as the backend
`statement`; an empty or non-read-only query is rejected at watch start. A tick
returning zero rows (or a NULL scalar) is treated as "no change"; transient
connect / query failures are logged and retried on the next tick.

## Security

- **Parameter binding is injection-safe** — bound values are ClickHouse SQL
  literals, never string-interpolated into the statement.
- **Read-only guard** (keyword check at register + server-side `readonly=1`).
- **Catalog filters bind, never interpolate** — the `list_tables` / `list_columns`
  database / table filters are bound query parameters; catalog ops are always
  read-only. `query.settings` is operator-config only (a caller can't widen it).
- **TLS verifies by default**, no opt-out (see above).
- **Bare `cred://` rejected** in operator-fixed strings; resolved secrets never
  logged / never reflected.
- The keyset `list_query.cursor_column` is fenced by a safe-identifier check
  (`[A-Za-z_][A-Za-z0-9_]*`) since it is interpolated into the cursor projection.
- `network_outbound` capability.

## Testing

Unit tests (`cargo test -p mcpg-plugin-backend-clickhouse --lib`) cover config
parse/validate (incl. `verify_peer: false` rejection), CEL params
compile/evaluate/scalar-map/non-scalar reject, the `JSONEachRow` → JSON
marshaller, the read-only guard, surface shaping, `list_query` + completion
validation, output/input schema, bare-cred reject, and that the client builds at
register without connecting — all offline. A real-ClickHouse testcontainer suite
drives a create → seed → parameterised read round-trip, a resource-surface read,
and an injection probe:

```bash
cargo test -p mcpg-plugin-backend-clickhouse \
    --features integration-tests --test integration -- --test-threads 1
```

(needs Docker; runs in the `--config=integration` CI lane — the bundled
`clickhouse/clickhouse-server` image has no auth, exercising the plain HTTP
path.)

## Notes

- rustls-only: `clickhouse` uses `default-features = false, features = ["lz4",
  "rustls-tls"]`. The `openssl` / `native-tls` Rust wrappers are banned by
  `deny.toml`; `cargo tree -i native-tls` / `-i openssl` are empty.
- Wired into the gateway via the closed `BackendImpl` enum (`kind: clickhouse`)
  like the other envelope backends.
```
