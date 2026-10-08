use crate::{Error, Result, assembly, error::invalid, model::*};
use serde_json::{Value, json};
use sqlx::{
    AnyPool, ConnectOptions, Row,
    any::{AnyConnectOptions, AnyPoolOptions},
};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone)]
pub struct Store {
    pub pool: AnyPool,
    sqlite: bool,
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self> {
        let sqlite = url.starts_with("sqlite:");
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(if sqlite { 1 } else { 16 })
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if sqlite {
                        sqlx::query("PRAGMA journal_mode=WAL")
                            .execute(&mut *connection)
                            .await?;
                        sqlx::query("PRAGMA busy_timeout=5000")
                            .execute(&mut *connection)
                            .await?;
                        return Ok(());
                    }
                    sqlx::query("SET statement_timeout = '15s'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET lock_timeout = '5s'")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(
                url.parse::<AnyConnectOptions>()?
                    .disable_statement_logging(),
            )
            .await?;
        let store = Self { pool, sqlite };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        if !self.sqlite {
            sqlx::query("SELECT pg_advisory_xact_lock(783248029)")
                .execute(&mut *tx)
                .await?;
        }
        let schema = if self.sqlite {
            include_str!("../schema.sql")
                .replace("BIGSERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
        } else {
            include_str!("../schema.sql").to_owned()
        };
        for statement in schema.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn get(&self, scope: &str, kind: &str, id: &str) -> Result<Record> {
        let row = sqlx::query(
            "SELECT version, definition FROM catalog_records WHERE scope=$1 AND kind=$2 AND id=$3",
        )
        .bind(scope)
        .bind(kind)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::NotFound)?;
        Ok(Record {
            version: row.try_get("version")?,
            definition: serde_json::from_str(&row.try_get::<String, _>("definition")?)?,
        })
    }

    pub async fn put(
        &self,
        scope: &str,
        kind: &str,
        id: &str,
        expected: i64,
        definition: Value,
        actor: &str,
    ) -> Result<Record> {
        name(scope)?;
        if kind == "auth_principal" { principal_id(id)?; } else { name(id)?; }
        if expected < 0 || expected == i64::MAX {
            return Err(invalid("invalid expected version"));
        }
        let mut tx = self.pool.begin().await?;
        let version = expected + 1;
        if expected == 0 {
            sqlx::query("INSERT INTO catalog_records(scope,kind,id,version,definition) VALUES($1,$2,$3,$4,$5)")
                .bind(scope).bind(kind).bind(id).bind(version).bind(serde_json::to_string(&definition)?).execute(&mut *tx).await?;
        } else {
            let updated = sqlx::query("UPDATE catalog_records SET version=$4,definition=$5 WHERE scope=$1 AND kind=$2 AND id=$3 AND version=$6")
                .bind(scope).bind(kind).bind(id).bind(version).bind(serde_json::to_string(&definition)?).bind(expected).execute(&mut *tx).await?;
            if updated.rows_affected() != 1 {
                return Err(Error::Conflict(
                    "version changed; reload before editing".into(),
                ));
            }
        }
        sqlx::query("INSERT INTO catalog_audit(scope,actor,action,object_id,version,at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(scope).bind(actor).bind(kind).bind(id).bind(version).bind(chrono::Utc::now().to_rfc3339()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Record {
            version,
            definition,
        })
    }

    pub async fn list(&self, scope: &str, kind: &str) -> Result<BTreeMap<String, Record>> {
        let rows = sqlx::query("SELECT id,version,definition FROM catalog_records WHERE scope=$1 AND kind=$2 ORDER BY id LIMIT 1001")
            .bind(scope).bind(kind).fetch_all(&self.pool).await?;
        if rows.len() > 1000 {
            return Err(invalid(
                "scope exceeds 1000 records; partition registrations into scopes",
            ));
        }
        rows.into_iter()
            .map(|r| {
                Ok((
                    r.try_get("id")?,
                    Record {
                        version: r.try_get("version")?,
                        definition: serde_json::from_str(&r.try_get::<String, _>("definition")?)?,
                    },
                ))
            })
            .collect()
    }

    pub async fn publish(
        &self,
        scope: &str,
        id: &str,
        request: Publish,
        actor: &str,
    ) -> Result<Manifest> {
        if request.expected_revision < 0 || request.expected_revision == i64::MAX {
            return Err(invalid("invalid expected revision"));
        }
        // Assemble from the exact reviewed versions. Concurrent draft edits may proceed;
        // this immutable release still contains precisely the reviewed definitions.
        let record = self.get(scope, "graph", id).await?;
        if record.version != request.graph_version {
            return Err(Error::Conflict("graph version changed".into()));
        }
        let graph: Graph = serde_json::from_value(record.definition)?;
        let mut selected = BTreeMap::new();
        let mut objects = BTreeMap::new();
        let mut pending = graph.objects.clone();
        pending.extend(graph.execution_connector.clone());
        while let Some(key) = pending.pop() {
            if selected.contains_key(&key) {
                continue;
            }
            if selected.len() >= 1000 {
                return Err(invalid("too many graph dependencies"));
            }
            let record = self.get(scope, "object", &key).await?;
            let object: Object = serde_json::from_value(record.definition.clone())?;
            pending.extend(dependencies(&object));
            objects.insert(key.clone(), object);
            selected.insert(key, record);
        }
        if selected
            .iter()
            .map(|(k, v)| (k.clone(), v.version))
            .collect::<BTreeMap<_, _>>()
            != request.object_versions
        {
            return Err(Error::Conflict(
                "dependency versions changed or are incomplete".into(),
            ));
        }
        let schema = assembly::assemble(&graph, &objects)?;
        let revision = request.expected_revision + 1;
        let manifest = Manifest {
            protocol_version: if graph.execution_connector.is_none()
                || objects
                    .values()
                    .any(|object| matches!(object["kind"].as_str(), Some("cypher_relationship")))
            {
                2
            } else {
                1
            },
            scope: scope.into(),
            graph: id.into(),
            revision,
            graph_version: record.version,
            description: graph.description,
            published_at: chrono::Utc::now(),
            objects: selected,
            schema,
        };
        let mut tx = self.pool.begin().await?;
        if request.expected_revision == 0 {
            sqlx::query("INSERT INTO catalog_records(scope,kind,id,version,definition) VALUES($1,'active',$2,$3,$4)")
                .bind(scope).bind(id).bind(revision).bind(json!({"revision": revision}).to_string()).execute(&mut *tx).await?;
        } else {
            let result = sqlx::query("UPDATE catalog_records SET version=$3,definition=$4 WHERE scope=$1 AND kind='active' AND id=$2 AND version=$5")
                .bind(scope).bind(id).bind(revision).bind(json!({"revision": revision}).to_string()).bind(request.expected_revision).execute(&mut *tx).await?;
            if result.rows_affected() != 1 {
                return Err(Error::Conflict("active revision changed".into()));
            }
        }
        sqlx::query(
            "INSERT INTO catalog_releases(scope,graph,revision,manifest) VALUES($1,$2,$3,$4)",
        )
        .bind(scope)
        .bind(id)
        .bind(revision)
        .bind(serde_json::to_string(&manifest)?)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO catalog_audit(scope,actor,action,object_id,version,at) VALUES($1,$2,'publish',$3,$4,$5)")
            .bind(scope).bind(actor).bind(id).bind(revision).bind(chrono::Utc::now().to_rfc3339()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(manifest)
    }

    pub async fn release(&self, scope: &str, id: &str, revision: Option<i64>) -> Result<Manifest> {
        let revision = match revision {
            Some(r) if r > 0 => r,
            Some(_) => return Err(invalid("invalid revision")),
            None => self.get(scope, "active", id).await?.version,
        };
        let row = sqlx::query(
            "SELECT manifest FROM catalog_releases WHERE scope=$1 AND graph=$2 AND revision=$3",
        )
        .bind(scope)
        .bind(id)
        .bind(revision)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::NotFound)?;
        Ok(serde_json::from_str(
            &row.try_get::<String, _>("manifest")?,
        )?)
    }

    pub async fn audit(&self, scope: &str) -> Result<Vec<Value>> {
        let rows = sqlx::query("SELECT actor,action,object_id,version,at FROM catalog_audit WHERE scope=$1 ORDER BY sequence DESC LIMIT 100")
            .bind(scope).fetch_all(&self.pool).await?;
        rows.into_iter().map(|r| Ok(json!({"actor":r.try_get::<String,_>("actor")?, "action":r.try_get::<String,_>("action")?, "object":r.try_get::<String,_>("object_id")?, "version":r.try_get::<i64,_>("version")?, "at":r.try_get::<String,_>("at")?}))).collect()
    }
}
