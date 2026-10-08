CREATE TABLE IF NOT EXISTS catalog_records (
    scope TEXT NOT NULL,
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    definition TEXT NOT NULL,
    PRIMARY KEY (scope, kind, id)
);
CREATE TABLE IF NOT EXISTS catalog_releases (
    scope TEXT NOT NULL,
    graph TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    manifest TEXT NOT NULL,
    PRIMARY KEY (scope, graph, revision)
);
CREATE TABLE IF NOT EXISTS catalog_audit (
    sequence BIGSERIAL PRIMARY KEY,
    scope TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS catalog_audit_scope_sequence ON catalog_audit(scope, sequence DESC);
