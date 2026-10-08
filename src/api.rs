use crate::{Error, Result, error::invalid, model::*, store::Store};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::sync::{RwLock, Semaphore};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

#[derive(Clone)]
pub struct App {
    pub store: Store,
    pub identities: Arc<RwLock<Vec<Identity>>>,
    publications: Arc<Semaphore>,
}

impl App {
    pub fn new(store: Store, identities: Vec<Identity>) -> Result<Self> {
        validate_identities(&identities)?;
        Ok(Self {
            store,
            identities: Arc::new(RwLock::new(identities)),
            publications: Arc::new(Semaphore::new(2)),
        })
    }
    async fn identity(&self, headers: &HeaderMap) -> Result<Principal> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error::Unauthorized)?;
        let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
        self.identities
            .read()
            .await
            .iter()
            .find(|i| bool::from(digest.as_bytes().ct_eq(i.sha256.as_bytes())))
            .map(|i| i.principal.clone())
            .ok_or(Error::Unauthorized)
    }
    async fn admin(&self, headers: &HeaderMap) -> Result<Principal> {
        let principal = self.identity(headers).await?;
        if !principal.admin {
            return Err(Error::Forbidden);
        }
        Ok(principal)
    }
    async fn authorize(
        &self,
        scope: &str,
        graph: &str,
        principal: &Principal,
        execute: bool,
    ) -> Result<()> {
        name(scope)?;
        name(graph)?;
        if principal.admin {
            return Ok(());
        }
        let record = self.store.get(scope, "grants", graph).await?;
        let grants: Grants = serde_json::from_value(record.definition)?;
        let allowed = principal
            .roles
            .iter()
            .any(|r| grants.execute.contains(r) || (!execute && grants.discover.contains(r)));
        if allowed {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }
}

pub fn validate_identities(identities: &[Identity]) -> Result<()> {
    if identities.is_empty() {
        return Err(invalid("at least one identity is required"));
    }
    let mut hashes = std::collections::BTreeSet::new();
    for identity in identities {
        if identity.sha256.len() != 64
            || !identity
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !hashes.insert(&identity.sha256)
        {
            return Err(invalid(
                "identity hashes must be unique lowercase SHA256 digests",
            ));
        }
        if identity.principal.subject.is_empty() {
            return Err(invalid("identity subject is required"));
        }
        for role in &identity.principal.roles {
            name(role)?;
        }
    }
    Ok(())
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route(
            "/v1/schema",
            get(|| async { Json(serde_json::from_str::<Value>(OBJECT_SCHEMA).expect("schema")) }),
        )
        .route("/v1/{scope}/objects", get(objects))
        .route("/v1/{scope}/objects/{id}", put(register).get(object))
        .route("/v1/{scope}/graphs", get(graphs))
        .route("/v1/{scope}/graphs/{id}", put(graph))
        .route("/v1/{scope}/graphs/{id}/draft", get(draft))
        .route(
            "/v1/{scope}/graphs/{id}/grants",
            put(grants).get(read_grants),
        )
        .route("/v1/{scope}/graphs/{id}/publish", post(publish))
        .route("/v1/{scope}/graphs/{id}/resolve", get(resolve))
        .route("/v1/{scope}/graphs/{id}/discover", get(discover))
        .route("/v1/{scope}/audit", get(audit))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(middleware::from_fn(response_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(app)
}

async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}

async fn health(State(app): State<App>) -> Result<Json<Value>> {
    sqlx::query("SELECT 1").execute(&app.store.pool).await?;
    Ok(Json(json!({"status":"ok", "protocol_version":1})))
}

async fn register(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Write<Object>>,
) -> Result<Json<Record>> {
    let principal = app.admin(&headers).await?;
    validate_object(&body.definition)?;
    Ok(Json(
        app.store
            .put(
                &scope,
                "object",
                &id,
                body.expected_version,
                serde_json::to_value(body.definition)?,
                &principal.subject,
            )
            .await?,
    ))
}
async fn object(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Record>> {
    app.admin(&headers).await?;
    Ok(Json(app.store.get(&scope, "object", &id).await?))
}
async fn objects(
    State(app): State<App>,
    Path(scope): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    app.admin(&headers).await?;
    Ok(Json(serde_json::to_value(
        app.store.list(&scope, "object").await?,
    )?))
}
async fn graph(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Write<Graph>>,
) -> Result<Json<Record>> {
    let principal = app.admin(&headers).await?;
    name(&body.definition.execution_connector)?;
    if body.definition.objects.is_empty() || body.definition.objects.len() > 1000 {
        return Err(invalid("graph requires 1..1000 objects"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in &body.definition.objects {
        name(id)?;
        if !seen.insert(id) {
            return Err(invalid("duplicate graph object"));
        }
    }
    Ok(Json(
        app.store
            .put(
                &scope,
                "graph",
                &id,
                body.expected_version,
                serde_json::to_value(body.definition)?,
                &principal.subject,
            )
            .await?,
    ))
}
async fn draft(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Record>> {
    app.admin(&headers).await?;
    Ok(Json(app.store.get(&scope, "graph", &id).await?))
}
async fn grants(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Write<Grants>>,
) -> Result<Json<Record>> {
    let principal = app.admin(&headers).await?;
    app.store.get(&scope, "graph", &id).await?;
    for role in body
        .definition
        .discover
        .iter()
        .chain(&body.definition.execute)
    {
        name(role)?;
    }
    Ok(Json(
        app.store
            .put(
                &scope,
                "grants",
                &id,
                body.expected_version,
                serde_json::to_value(body.definition)?,
                &principal.subject,
            )
            .await?,
    ))
}
async fn read_grants(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Record>> {
    app.admin(&headers).await?;
    Ok(Json(app.store.get(&scope, "grants", &id).await?))
}
async fn publish(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Publish>,
) -> Result<Json<Manifest>> {
    let principal = app.admin(&headers).await?;
    let _permit = app
        .publications
        .try_acquire()
        .map_err(|_| Error::Conflict("publication capacity reached; retry later".into()))?;
    Ok(Json(
        app.store
            .publish(&scope, &id, body, &principal.subject)
            .await?,
    ))
}

#[derive(Default, Deserialize)]
struct Read {
    revision: Option<i64>,
    #[serde(default)]
    q: String,
}

async fn resolve(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Query(read): Query<Read>,
    headers: HeaderMap,
) -> Result<Json<Resolved>> {
    let principal = app.identity(&headers).await?;
    app.authorize(&scope, &id, &principal, true).await?;
    Ok(Json(Resolved {
        manifest: app.store.release(&scope, &id, read.revision).await?,
        principal,
    }))
}
async fn discover(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Query(read): Query<Read>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let principal = app.identity(&headers).await?;
    app.authorize(&scope, &id, &principal, false).await?;
    if read.q.len() > 256 {
        return Err(invalid("search text too long"));
    }
    let release = app.store.release(&scope, &id, read.revision).await?;
    let query = read.q.to_lowercase();
    let objects: Vec<Value> = release
        .objects
        .into_iter()
        .filter_map(|(id, mut record)| {
            if record.definition["kind"] == "connector" {
                return None;
            }
            if !format!("{id} {}", record.definition)
                .to_lowercase()
                .contains(&query)
            {
                return None;
            }
            if let Some(object) = record.definition.as_object_mut() {
                object.remove("connector");
                object.remove("iceberg");
            }
            Some(json!({"id":id,"version":record.version,"definition":record.definition}))
        })
        .collect();
    Ok(Json(
        json!({"revision": release.revision,"description":release.description,"objects":objects}),
    ))
}
async fn graphs(
    State(app): State<App>,
    Path(scope): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let principal = app.identity(&headers).await?;
    let mut visible = Vec::new();
    for (id, _) in app.store.list(&scope, "active").await? {
        match app.authorize(&scope, &id, &principal, false).await {
            Ok(()) => (),
            Err(Error::NotFound) => continue,
            Err(e) => return Err(e),
        }
        let release = app.store.release(&scope, &id, None).await?;
        visible
            .push(json!({"id":id,"revision":release.revision,"description":release.description}));
    }
    Ok(Json(json!(visible)))
}
async fn audit(
    State(app): State<App>,
    Path(scope): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    app.admin(&headers).await?;
    Ok(Json(json!(app.store.audit(&scope).await?)))
}
