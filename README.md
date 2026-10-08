# Orchid Catalog

A small Rust HTTP catalog for OrchidDB. Register datasets, entities, relationships,
connectors, and retrieval definitions as JSON. Publish an immutable graph release;
embedded engines load its schema on their next startup. Agents discover the same
release through a permission-filtered endpoint.

The server uses Axum, Tokio, JSON Schema, and SQLx. It does **not** depend on
OrchidDB, Arrow, DataFusion, or search-engine SDKs. Its job is metadata, not query
execution. There is one binary and one storage setting: SQLite or PostgreSQL.

## Run locally

Requires Rust 1.92 or later. Create a random administrator credential:

```sh
umask 077
export CATALOG_TOKEN="$(openssl rand -hex 32)"
TOKEN_HASH="$(printf '%s' "$CATALOG_TOKEN" | openssl dgst -sha256 -r | cut -d ' ' -f 1)"
printf '[{"sha256":"%s","principal":{"subject":"local-admin","admin":true}}]\n' "$TOKEN_HASH" > identities.json
export ORCHID_CATALOG_IDENTITIES="$PWD/identities.json"
export ORCHID_CATALOG_DATABASE="sqlite://catalog.db?mode=rwc"
cargo run --locked --release
```

The service listens on `127.0.0.1:8182`. Set `ORCHID_CATALOG_LISTEN` to change it.
There is no anonymous metadata access and no default credential.

In another terminal, with the same `CATALOG_TOKEN`:

```sh
export CATALOG_URL=http://127.0.0.1:8182
export CATALOG_SCOPE=demo
cargo run --locked --example register -- examples/social.json
curl -fsS -H "Authorization: Bearer $CATALOG_TOKEN" \
  "$CATALOG_URL/v1/demo/graphs/social/discover"
curl -fsS -H "Authorization: Bearer $CATALOG_TOKEN" \
  "$CATALOG_URL/v1/demo/graphs/social/resolve"
```

The registration example creates a new graph in an empty scope. Existing records
return conflicts; it deliberately does not overwrite them automatically.

## API

All metadata endpoints require a bearer token. Names are ASCII identifiers up to
128 characters. Object contracts are in [schemas/object.json](schemas/object.json),
also served at `GET /v1/schema`. Bodies are limited to 1 MiB.

| Method and path | Result / permission |
| --- | --- |
| `GET /healthz` | Database readiness; public |
| `GET /v1/schema` | JSON Schema contract; public |
| `PUT /v1/{scope}/objects/{id}` | Register/update one draft; administrator |
| `GET /v1/{scope}/objects[/{id}]` | Inspect drafts; administrator |
| `PUT /v1/{scope}/graphs/{id}` | Register/update graph roots; administrator |
| `GET /v1/{scope}/graphs/{id}/draft` | Graph draft; administrator |
| `PUT/GET /v1/{scope}/graphs/{id}/grants` | Live access grants; administrator |
| `POST /v1/{scope}/graphs/{id}/publish` | Validate and atomically publish; administrator |
| `GET /v1/{scope}/graphs` | List accessible published graphs |
| `GET /v1/{scope}/graphs/{id}/discover` | Semantic metadata; discover or execute grant |
| `GET /v1/{scope}/graphs/{id}/resolve` | Complete engine manifest; execute grant |
| `GET /v1/{scope}/audit` | Latest 100 mutations; administrator |

`discover` and `resolve` accept `?revision=N`; omission selects the active release.
`discover` accepts `?q=text` to filter names and descriptions. Discovery omits
connector definitions and physical Iceberg references. It includes keys, columns,
relationship endpoints, descriptions, cardinality declarations, ranking rules,
retrieval inputs, limits, and freshness metadata.

Draft writes use an optimistic version:

```json
{
  "expected_version": 0,
  "definition": {
    "kind": "connector",
    "description": "Application-owned SQL engine",
    "adapter": "duckdb",
    "protocol_version": 1
  }
}
```

Zero creates a record. An update must supply the last returned version. Unknown
JSON fields fail validation. Administrators can edit objects separately, including
relationships that are not yet part of a published graph.

A graph specifies root objects and an execution connector. Publication walks all
dependencies and requires the exact reviewed graph and object versions:

```json
{
  "expected_revision": 0,
  "graph_version": 1,
  "object_versions": {
    "local": 1,
    "people": 1,
    "person": 1,
    "links": 1,
    "follows": 1
  }
}
```

The server validates JSON Schema, dependency kinds, table/label uniqueness,
property references, endpoint key arity/types, and ranked-edge ordering. Expressions
and provider capabilities are validated by the engine when binding the manifest.
Cardinality and key uniqueness are declarations, not verified data constraints.

Publication commits the release, active pointer, and audit record in one database
transaction. Concurrent publication uses compare-and-swap; one writer wins.
Draft changes do not alter existing releases. Old releases remain readable under
**current** grants, so pinning an old revision does not restore revoked access.
To roll back, republish the reviewed definitions from an earlier release as a new
revision; history is never rewritten.

## Loading an embedded engine

The resolve response contains `manifest.schema`, using OrchidDB's existing schema
registration format, plus versioned connector/retrieval definitions in
`manifest.objects`. The host supplies its installed adapters and credentials.

In an application that already depends on OrchidDB and an HTTP client:

```rust,ignore
let resolved: serde_json::Value = http
    .get(format!("{catalog}/v1/company/graphs/knowledge/resolve"))
    .bearer_auth(&token)
    .send().await?.error_for_status()?.json().await?;
let manifest = &resolved["manifest"];
let schema = orchiddb_client::Schema::from_value(manifest["schema"].clone())?;
let graph = orchiddb_client::Connection::new(engine, schema);
// Execute normal graph queries through graph; retain manifest["revision"].
```

For multiple engines, supply the registered sessions to OrchidDB's existing
`FederatedConnection`. The catalog does not download plugins, open arbitrary
connector endpoints, or attach data. Unsupported adapters must fail at the host.
Long-lived applications should refresh between queries or reopen their connection,
never replace mappings midway through a query. Recheck authorization before each
query if revocation must affect an existing connection; a previously downloaded
manifest cannot revoke credentials already held by an application.

## Iceberg, Polaris, and search

A dataset can include an `iceberg` reference with catalog, namespace, table UUID,
and schema ID, plus a `field_id` on each column. Polaris stays authoritative for
table metadata, snapshots, and storage credential delegation. The host resolves
the reference through Iceberg REST and verifies schema compatibility before
binding it to the local table alias. The catalog stores references, not copied
Iceberg table metadata or vended credentials.

[Search registrations](examples/search-registrations.json) illustrate independent
Weaviate and Quickwit registrations. Replace the endpoints and register their
target entities (`document`, `log_event`) before including them in a graph.

Connector names, adapter names, capability strings, and retrieval modes are
extensible metadata. Installing a new backend does not require changing this
server. Each connector includes a protocol version and a secret **reference**.
Actual credentials remain in the embedding application's secret provider.

Stored relationships and computed graph mappings appear in `manifest.schema`.
Search operations also carry target identity, input/output JSON Schemas, index or
collection name, score meaning, tenant requirements, candidate limits, and optional
source snapshot/watermark in `manifest.objects`. Dataset `source_metadata` can
describe an existing OrchidDB index binding, including its owning connector.

Registration does not build indexes or install a Weaviate adapter. Index ingestion,
updates, deletes, tenant filtering, ranking semantics, and enforcement of freshness
bounds belong to the provider adapter and its ingestion process. A catalog revision
is not a distributed data snapshot.

## Permissions and deployment

Identities are SHA256 hashes of random bearer tokens mapped to subjects, roles,
and an optional trusted tenant. Identity files contain hashes, not tokens. Give
each workload a separate random token and mount this file as a deployment secret.
Send `SIGHUP` to atomically reload identities after rotation or revocation. An
invalid replacement disables access until a successful reload. No per-request
filesystem reads are needed.

Administrators can mutate all scopes. Ordinary roles are granted access per graph:

```json
{
  "expected_version": 0,
  "definition": {"discover": ["analyst"], "execute": ["application"]}
}
```

Execute includes discovery. Missing grants deny access. These are catalog-level
permissions; row/column authorization remains with the trusted query host and
storage system. Never give an untrusted embedded client unrestricted base-table
credentials and expect catalog grants to protect those files. OIDC, row-policy
administration, and a query gateway are not implemented in this first version.

- **SQLite:** one service instance, local durable disk, WAL enabled. Suitable for
  local development and modest single-instance production. Do not place the DB on
  a shared network filesystem. Back up with SQLite's backup API or `VACUUM INTO`.
- **PostgreSQL:** set `ORCHID_CATALOG_DATABASE=postgres://...`; use TLS in production.
  Multiple service replicas share the same database and identity configuration.
  Use normal PostgreSQL backup/restore and access controls. An advisory lock
  serializes initial schema creation.
- Put TLS termination, rate limiting, and connection limits at the ingress. The
  server binds loopback by default, bounds request bodies and database waits, and
  has a 30-second HTTP deadline. All metadata responses use `Cache-Control: no-store`.
- Shutdown drains HTTP requests on SIGTERM/SIGINT. `RUST_LOG` controls tracing.
  The database records successful metadata mutations without credentials.
- The database schema is version 1 and is created on startup. Future schema
  changes need explicit migrations; there is no destructive auto-migration.
- `Dockerfile` builds a standalone non-root image. Mount identities and persistent
  SQLite storage, or configure an external PostgreSQL database.

For a local PostgreSQL instance, set `POSTGRES_PASSWORD`, run `docker compose up -d`,
and use the exposed port `55432` with database/user `orchid_catalog`.

## Verification

```sh
cargo test --locked
CATALOG_TEST_POSTGRES=postgres://user:password@127.0.0.1:55432/database cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release --bin orchid-catalog
```

The same HTTP contract suite exercises SQLite and PostgreSQL: concurrent
publication, immutable releases, stale-version rejection, invalid endpoint types,
access grants, revocation, and audit atomicity. PostgreSQL tests require the
environment variable; otherwise that scenario is skipped.
