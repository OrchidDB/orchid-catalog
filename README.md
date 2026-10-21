# Orchid Catalog

A small Rust HTTP catalog for OrchidDB. Register datasets, entities, relationships,
Cypher relationships, connectors, and retrieval definitions through the client APIs
or HTTP API. Publish an immutable graph release; embedded engines resolve the
active or pinned revision for each query. Agents discover the same
release through a permission-filtered endpoint.

The server uses Axum, Tokio, JSON Schema, and SQLx. It does **not** depend on
OrchidDB, Arrow, DataFusion, or search-engine SDKs. Its job is metadata, not query
execution. There is one binary and one storage setting: SQLite or PostgreSQL.

## Architecture

![Catalog system architecture](docs/architecture/01-system.svg)

The [architecture diagram](docs/architecture/README.md) includes editable Graphviz
source and SVG/PNG exports.

## Run locally

Download the macOS Apple Silicon binary or the portable source archive from
[GitHub Releases](https://github.com/OrchidDB/orchid-catalog/releases).
Verify the archive against the release's `SHA256SUMS` before extracting it.
The binary archive includes `bin/orchid-catalog`; use that executable in place
of `cargo run --locked --` in the bootstrap command below, and in place of
`cargo run --locked` when starting the service. Linux and other architectures
can build the source archive with `cargo build --locked --release`.

Requires Rust 1.92 or later. Bootstrap a local administrator and signing key:

```sh
cargo run --locked -- bootstrap ./catalog-secrets
export ORCHID_CATALOG_AUTH_CONFIG="$PWD/catalog-secrets/auth.json"
export ORCHID_CATALOG_DATABASE="sqlite://catalog.db?mode=rwc"
cargo run --locked
```

Bootstrap creates a new directory with owner-only permissions, a symmetric signing
key, an administrator credential file, and the authentication configuration. It
refuses to overwrite an existing directory. There is no default credential or
anonymous metadata access. The service listens on `127.0.0.1:8182`; configure
`ORCHID_CATALOG_LISTEN` to change it.

Clients can use OAuth directly with client ID `admin` and the credential in
`catalog-secrets/admin.secret`. The token endpoint for scope `demo` is
`http://127.0.0.1:8182/v1/demo/oauth/tokens`. To use the existing registration program:

```sh
export CATALOG_URL=http://127.0.0.1:8182
export CATALOG_SCOPE=demo
export CATALOG_TOKEN="$(curl --fail --silent --show-error \
  "$CATALOG_URL/v1/$CATALOG_SCOPE/oauth/tokens" \
  --data-urlencode client_id=admin \
  --data-urlencode client_secret@catalog-secrets/admin.secret \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode scope=PRINCIPAL_ROLE:ALL | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
cargo run --locked --example register -- examples/social.json
```

The registration example creates a new graph in an empty scope. Existing records
return conflicts; it deliberately does not overwrite them automatically.

## API

All metadata endpoints require a bearer token. Names are ASCII identifiers up to
128 characters. Object contracts are in [schemas/object.json](schemas/object.json),
also served to authenticated callers at `GET /v1/{scope}/schema`
(`GET /v1/schema` uses the default scope). Bodies are limited to 1 MiB.

| Method and path | Result / permission |
| --- | --- |
| `GET /healthz` | Database readiness; public |
| `GET /v1/schema` | JSON Schema contract; authenticated |
| `PUT /v1/{scope}/objects/{id}` | Register/update one draft; administrator |
| `GET /v1/{scope}/objects[/{id}]` | Inspect drafts; administrator |
| `PUT /v1/{scope}/graphs/{id}` | Register/update graph roots; administrator |
| `GET /v1/{scope}/graphs/{id}/draft` | Graph draft; administrator |
| `PUT/GET /v1/{scope}/graphs/{id}/grants` | Live access grants; administrator |
| `POST /v1/{scope}/graphs/{id}/publish` | Validate and atomically publish; administrator |
| `GET /v1/{scope}/graphs` | List accessible published graphs |
| `GET /v1/{scope}/graphs/{id}/discover` | Semantic metadata; discover or execute grant |
| `GET /v1/{scope}/graphs/{id}/resolve` | Complete engine manifest; execute grant |
| `GET /v1/{scope}/audit` | Latest 100 mutations; authorized administrator |

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

A graph specifies root objects and an optional execution connector. Definitions-only
graphs omit the connector. Publication walks all
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

## Declarative Cypher relationships

Register a `cypher_relationship` through the existing object API. Its signature is
represented by its name and JSON Schema parameters; its body is Cypher. There is
no separate expression language. For example, `SIMILAR(k = 10, min_score = 0.8)`:

```json
{
  "kind": "cypher_relationship",
  "description": "Exact geometric similarity, ranked per source shape",
  "name": "SIMILAR",
  "source": "shape",
  "target": "shape",
  "parameters": [
    {"name": "k", "schema": {"type": "integer", "minimum": 1, "maximum": 1000}, "default": 10},
    {"name": "min_score", "schema": {"type": "number", "minimum": 0, "maximum": 1}, "default": 0.8}
  ],
  "cypher": "WITH source MATCH (target:Shape) WHERE target.id <> source.id WITH target, robotics.geometry.similarity(source.geometry, target.geometry) AS score WHERE score >= $min_score RETURN target, score ORDER BY score DESC, target.id LIMIT $k",
  "returns": {
    "target": "target",
    "properties": {"score": {"type": "number", "minimum": 0, "maximum": 1}}
  }
}
```

`shape` references a registered entity. The Cypher body calls
`robotics.geometry.similarity`, which is supplied and resolved by the runner.
Functions and procedures are not catalog objects. Row-returning procedure calls
use ordinary Cypher `CALL ... YIELD` inside the relationship body:

```cypher
WITH source
CALL search.neighbors('document_embeddings', source.embedding, source.id, $k)
YIELD target_id, score
MATCH (target:Document {id: target_id})
RETURN target, score
ORDER BY score DESC, target.id
```

The complete [registration bundle](examples/declarative-relationships.json) includes
both edges, their entities, and datasets. Register and publish
it in a fresh scope using the existing example client:

```sh
CATALOG_SCOPE=declarative cargo run --locked --example register -- examples/declarative-relationships.json
```

The catalog validates parameter and return schemas, defaults, unique names, entity
endpoints. Contract schemas must be self-contained;
internal `$ref` references are supported, external schema retrieval is disabled.
Publication requires reviewed versions for the relationship, entity, and dataset
dependency closure. Discovery exposes the Cypher body, parameters, results, and
descriptions. No runner or backend needs to be online for publication.

### Runner contract

- Each body is a correlated Cypher query with one source node bound as the variable
  `source`. The node exposes the source entity's mapped properties. The body runs
  logically once per source, so `LIMIT $k` is per source even when execution is batched.
- Parameters without defaults are required. The runner applies defaults and validates
  supplied arguments against their schemas, then binds `$name` parameters without
  interpolating query text. In a derived relationship pattern, declared parameter
  names in `{score: $minimumScore, limit: $limit}` bind expansion arguments; other
  keys remain property equality filters. Parameter names take precedence when a
  returned property has the same name. Explicit `WHERE r.score ...` predicates
  filter the resulting edges. Each pattern occurrence binds independently.
  Parameter schemas can include descriptions explaining their meaning.
- Each result row produces an outgoing edge. `returns.target` names the column
  containing the target node; `returns.properties` names the other result columns
  and their schemas. The runner checks the declared target entity and result types.
  Ordering and duplicate elimination are expressed in the Cypher body. Reverse
  traversal is not implied by a forward definition.
- The runner parses and binds the body and resolves function and procedure calls
  against its own registry. Function signatures, versions, and implementations are
  managed by the runner. Unknown symbols or incompatible calls fail binding.
- Implementations, endpoint bindings, adapters, and credentials belong to the runner.
  A deployment can implement a symbol locally or through a service. The catalog
  distributes definitions only and never downloads or executes function code.
- The runner enforces read-only edge bodies/procedures, data authorization, and query
  resource limits. Catalog acceptance is structural validation, not Cypher compilation
  or a guarantee that a deployment can execute the definition.

Definitions-only graphs and graphs containing Cypher relationships publish
`protocol_version: 2`. Their authoritative definitions are the versioned records in
`manifest.objects`; `manifest.schema` retains legacy table/mapping metadata and does
not lower Cypher edges. Runners must explicitly support version 2 and perform that
lowering. Existing connector-based graphs without these kinds remain version 1.
A release pins relationship definitions, not runner function versions, service
binaries, or data snapshots.

## Loading an embedded engine

The resolve response contains `manifest.schema`, using OrchidDB's existing schema
registration format, plus versioned connector/retrieval definitions in
`manifest.objects`. The host supplies its installed adapters and credentials.

For a legacy version-1 release, in an application that already depends on OrchidDB
and an HTTP client:

```rust,ignore
let resolved: serde_json::Value = http
    .get(format!("{catalog}/v1/company/graphs/knowledge/resolve"))
    .bearer_auth(&token)
    .send().await?.error_for_status()?.json().await?;
let manifest = &resolved["manifest"];
assert_eq!(manifest["protocol_version"], 1, "this example handles legacy mappings only");
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

## External references and execution backends

A dataset can include an `iceberg` reference with catalog, namespace, table UUID,
and schema ID, plus a `field_id` on each column. Polaris stays authoritative for
table metadata, snapshots, and storage credential delegation. The host resolves
the reference through Iceberg REST and verifies schema compatibility before
binding it to the local table alias. The catalog stores references, not copied
Iceberg table metadata or vended credentials.

Execution backends are completely orthogonal to this catalog. A backend name is
registration data, not an integration, dependency, or supported-provider list.
The catalog never contacts registered endpoints or checks backend availability.
Consumers decide how to interpret and execute the published binding contracts.
Adding or replacing a backend requires no catalog code change or deployment.

[Search registration examples](examples/search-registrations.json) show generic
connector and retrieval metadata. Register their target entities (`document`,
`log_event`) before including them in a graph. These are sample documents, not
built-in backend integrations.

Connector names, adapter names, capability strings, and retrieval modes are
extensible metadata. Each connector includes a protocol version and may include
a secret **reference**. Actual credentials remain with the consuming application.

Stored relationships and computed graph mappings appear in `manifest.schema`.
Search operations also carry target identity, input/output JSON Schemas, index or
collection name, score meaning, tenant requirements, candidate limits, and optional
source snapshot/watermark in `manifest.objects`. Dataset `source_metadata` can
describe an existing OrchidDB index binding, including its owning connector.

Index ingestion,
updates, deletes, tenant filtering, ranking semantics, and enforcement of freshness
bounds belong entirely to the consuming system. A catalog revision
is not a distributed data snapshot.

## Permissions and deployment

The executable reads `ORCHID_CATALOG_AUTH_CONFIG`, containing a `default` policy
and optional `scopes` policy overrides. Authentication options follow
[Apache Polaris](https://polaris.apache.org/releases/1.8.0/managing-security/external-idp/):
`internal`, `external`, and `mixed`. A policy is selected from the requested catalog
scope before authentication. Internal tokens are bound to that scope. Scope
overrides provide authentication isolation on the existing namespace; they do not
introduce another catalog hierarchy.

#### Internal OAuth

Bootstrap produces a policy of this form (actual secrets stay in protected files):

```json
{
  "default": {
    "mode": "internal",
    "internal": {
      "issuer": "orchid-catalog",
      "audience": "orchid-catalog",
      "token_lifetime_seconds": 3600,
      "signing": {"type": "symmetric", "key_file": "/run/secrets/signing.key"},
      "clients": [{
        "client_id": "admin",
        "secret_sha256": "<SHA256 of the generated client secret>",
        "principal": {"subject": "admin", "roles": ["service_admin"], "admin": true}
      }]
    }
  }
}
```

For RSA signing, replace `signing` with
`{"type":"rsa","private_key_file":"/run/secrets/private.pem","public_key_file":"/run/secrets/public.pem"}`.
All service replicas use the same keys and database. Signing keys are validated as
a pair at startup. Symmetric keys require at least 32 bytes.

`POST /v1/{scope}/oauth/tokens` accepts form-encoded `client_credentials` grants,
with credentials in the request body or HTTP Basic authorization. `scope` selects
`PRINCIPAL_ROLE:<role>` values, or `PRINCIPAL_ROLE:ALL`. Omitting it activates no
roles. The administrator capability requires `PRINCIPAL_ROLE:service_admin` or
`PRINCIPAL_ROLE:ALL`. Responses contain `access_token`, `token_type`, and
`expires_in`.

The same endpoint supports `urn:ietf:params:oauth:grant-type:token-exchange` with an
unexpired internal `subject_token` and its `subject_token_type` (access token or
JWT). The exchange can preserve or narrow active privileges and cannot change
identity or catalog scope. Actor-token delegation and cross-audience exchange are
not accepted. The external-only mode disables the internal token endpoint with
the same generic authentication failure used for rejected credentials. For external token exchange, clients call their configured IdP endpoint.

Administrators use these authenticated endpoints to manage workloads:

| Endpoint | Operation |
| --- | --- |
| `GET /v1/{scope}/principals` | List registered principals without credential hashes |
| `GET /v1/{scope}/principals/{id}` | Read principal and version |
| `PUT /v1/{scope}/principals/{id}` | Create, rotate, update, or disable with expected version |

A principal write contains `expected_version` and
`definition: {principal: {subject, roles, admin, tenant}, enabled}`. Each write
generates a new random secret and returns it once as `client_secret`, along with
`client_id` and `version`. The database stores only its SHA256 digest. Updating a
bootstrap principal creates an override in the database. Disablement and rotation
invalidate previously issued internal access tokens immediately; active roles are
also intersected with current principal permissions on every request. Bootstrap
credentials are used only when no database record exists for that ID.

#### External OIDC

```json
{
  "default": {
    "mode": "external",
    "external": {
      "issuer": "https://identity.example.com/realms/company",
      "audience": "orchid-catalog",
      "subject_claim": "sub",
      "roles_claim": "realm_access/roles",
      "role_filter": "^orchid_.*$",
      "role_mappings": [{"regex": "^orchid_(.*)$", "replacement": "$1"}],
      "admin_roles": ["service_admin"],
      "require_registered_principal": false
    }
  }
}
```

OIDC discovery locates the issuer's JWKS endpoint; `jwks_uri` can configure it
explicitly. JWT verification checks the signature, algorithm, issuer, audience,
expiry, and `nbf` when present. It accepts asymmetric signing only. Keys are cached
for five minutes; unknown keys and signature failures trigger a throttled refresh
for key rotation. Key URLs from tokens themselves are never fetched.

Claim paths use `/` for nesting. `subject_claim` selects the stable ID; optional
`name_claim` selects its display/audit name. String and numeric IDs are accepted. Roles may be a JSON array or a space-separated
string. Filtering and ordered regex replacements map IdP roles into catalog roles;
`PRINCIPAL_ROLE:` prefixes are accepted. No external role implicitly grants
administrator access: configure `admin_roles` explicitly. Optional `tenant_claim`
extracts the trusted tenant value.

`require_registered_principal` defaults to true: the mapped subject must match a
registered principal ID, and token roles are intersected with that principal's
current roles. Set it to false to trust the configured IdP's mapped subjects and
roles directly. Provision local principals while using internal or mixed mode
before switching to external authentication with registration required.

For opaque tokens or deployments requiring online validation, configure
`external.introspection` with `endpoint`, `client_id`, and `client_secret_env`.
The service authenticates to that endpoint and requires `active: true`, a matching
issuer and audience, and a future expiration before applying the same claim
mapping. JWTs can also use introspection. Introspection responses are not cached,
so the provider can revoke access on the next request. No graph metadata is sent
to the identity provider.

#### Mixed mode and scope overrides

A `mixed` policy includes both `internal` and `external` configurations. Internal
verification is attempted first, followed by the configured external provider.
Add complete policies under `scopes`, for example `scopes.production`, to assign a
different provider or authentication mode to an existing scope. Use distinct IdP
audiences when scopes must reject each other's external tokens.

On Unix, `SIGHUP` atomically reloads configuration and keys. Invalid replacements
disable authentication until a successful reload. Credential issuance and updates
use the existing versioned storage contract; there is no additional service or
credential database. The executable no longer uses `ORCHID_CATALOG_IDENTITIES` or
manually registered permanent bearer tokens. `App::new` retains the legacy
in-process identity adapter for existing embedders; the executable uses
`App::with_authentication`.

Administrators can mutate metadata in the scope where their credentials authenticate. Ordinary roles are granted access per graph:

```json
{
  "expected_version": 0,
  "definition": {"discover": ["analyst"], "execute": ["application"]}
}
```

Execute includes discovery. Missing grants deny access. These are catalog-level
permissions; row/column authorization remains with the trusted query host and
storage system. Never give an untrusted embedded client unrestricted base-table
credentials and expect catalog grants to protect those files. Row-policy administration and a query gateway are not implemented.

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
- `Dockerfile` builds a standalone non-root image. Mount authentication configuration, signing keys, and persistent
  SQLite storage, or configure an external PostgreSQL database.

For a local PostgreSQL instance, set `POSTGRES_PASSWORD`, run `docker compose up -d`,
and use the exposed port `55432` with database/user `orchid_catalog`.

## Authentication and client smoke flow

The client obtains a token from this service or a configured identity provider.
Authentication runs before metadata parsing. Graph discovery and resolution then
check current grants, including when a client pins a revision. The query host
executes locally; neither query text nor catalog metadata goes to the identity
provider. Client-credential tokens renew on demand. Internal secret rotation or
principal disablement invalidates previously issued internal tokens.

Run the service authentication smoke checks against a local debug binary:

```sh
cargo build --locked
python3 tools/auth_smoke.py
```

The fixture uses temporary SQLite storage and a local OIDC/JWKS/introspection
server. It checks internal symmetric and RSA signing, role selection, token
exchange, expiry and claim rejection, mixed mode, rotation, revocation, and
fail-closed configuration reload. For all six language clients, CLI, and extension
execution on DuckDB, run `make catalog-smoke` from the sibling OrchidDB repository.
Neither smoke command runs conformance or a release.

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


## Metadata boundary

All metadata routes authenticate before request parsing. Discovery and resolution
check current graph grants before reading published definitions or accepting
revision/search parameters. Unauthorized graph reads use the same response as
missing graphs; graph listings include only authorized entries. Error
responses contain status descriptions, without names, definitions, query text,
or database diagnostics. Responses disable intermediary caching.

Discovery filters private connector and Iceberg fields before evaluating search
text, so hidden values cannot influence matches. Operational logs omit request
paths, search strings, bodies, credentials, and database statements. The service
emits only its own fixed operational messages; dependency tracing is disabled.
Mutation audit records remain protected metadata in the catalog database.

Deploy the database, audit records, backups, TLS termination, proxy logs, and
application result handling inside the authorized boundary. The loopback HTTP
listener is intended for local use or a trusted TLS terminator. Catalog clients
require HTTPS for non-loopback endpoints and do not inherit ambient proxy settings.
Authorization cannot recall metadata already delivered to an authorized client;
applications must protect their retained snapshots and intentional exports.
