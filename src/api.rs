use crate::{Error, Result, error::invalid, model::*, store::Store};
use axum::{
    Extension, Form, Json, Router,
    extract::{DefaultBodyLimit, FromRequestParts, MatchedPath, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::sync::{RwLock, Semaphore};
use tower_http::timeout::TimeoutLayer;

#[derive(Clone)]
pub struct App {
    pub store: Store,
    pub identities: Arc<RwLock<Vec<Identity>>>,
    publications: Arc<Semaphore>,
    pub authentication: Arc<RwLock<Option<Arc<crate::auth::Authenticator>>>>,
}

impl App {
    pub fn new(store: Store, identities: Vec<Identity>) -> Result<Self> {
        validate_identities(&identities)?;
        Ok(Self {
            store,
            identities: Arc::new(RwLock::new(identities)),
            publications: Arc::new(Semaphore::new(2)),
            authentication: Arc::new(RwLock::new(None)),
        })
    }
    pub fn with_authentication(store: Store, authentication: crate::auth::Authenticator) -> Self {
        Self {
            store,
            identities: Arc::new(RwLock::new(Vec::new())),
            publications: Arc::new(Semaphore::new(2)),
            authentication: Arc::new(RwLock::new(Some(Arc::new(authentication)))),
        }
    }
    async fn identity(&self, headers: &HeaderMap, scope: &str) -> Result<Principal> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error::Unauthorized)?;
        if let Some(auth) = self.authentication.read().await.clone() {
            return auth.authenticate(&self.store, scope, token).await;
        }
        let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
        self.identities
            .read()
            .await
            .iter()
            .find(|i| bool::from(digest.as_bytes().ct_eq(i.sha256.as_bytes())))
            .map(|i| i.principal.clone())
            .ok_or(Error::Unauthorized)
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
        .route("/v1/{scope}/oauth/tokens", post(token))
        .route("/v1/{scope}/principals", get(principals))
        .route(
            "/v1/{scope}/principals/{id}",
            get(principal).put(register_principal),
        )
        .route(
            "/v1/schema",
            get(|| async { Json(serde_json::from_str::<Value>(OBJECT_SCHEMA).expect("schema")) }),
        )
        .route(
            "/v1/{scope}/schema",
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
        .layer(middleware::from_fn_with_state(app.clone(), access_gate))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(middleware::from_fn(response_headers))
        .with_state(app)
}

async fn access_gate(State(app): State<App>, request: Request, next: Next) -> Response {
    if request.uri().path() == "/healthz" {
        return next.run(request).await;
    }
    let (mut parts, body) = request.into_parts();
    let route = parts
        .extensions
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_default();
    if route == "/v1/{scope}/oauth/tokens" {
        return next.run(Request::from_parts(parts, body)).await;
    }
    let params = if route.contains("{scope}") {
        match Path::<std::collections::HashMap<String, String>>::from_request_parts(
            &mut parts, &app,
        )
        .await
        {
            Ok(Path(params)) => params,
            Err(_) => return Error::Unauthorized.into_response(),
        }
    } else {
        Default::default()
    };
    let scope = params.get("scope").map(String::as_str).unwrap_or("default");
    let principal = match app.identity(&parts.headers, scope).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    if route.contains("{scope}") {
        let Some(scope) = params.get("scope") else {
            return Error::NotFound.into_response();
        };
        let administration = !matches!(
            route.as_str(),
            "/v1/{scope}/schema"
                | "/v1/{scope}/graphs"
                | "/v1/{scope}/graphs/{id}/discover"
                | "/v1/{scope}/graphs/{id}/resolve"
        );
        if administration && !principal.admin {
            return Error::Forbidden.into_response();
        }
        if matches!(
            route.as_str(),
            "/v1/{scope}/graphs/{id}/discover" | "/v1/{scope}/graphs/{id}/resolve"
        ) {
            let Some(id) = params.get("id") else {
                return Error::NotFound.into_response();
            };
            if let Err(error) = app
                .authorize(scope, id, &principal, route.ends_with("/resolve"))
                .await
            {
                return error.into_response();
            }
        }
    }
    parts.extensions.insert(principal);
    next.run(Request::from_parts(parts, body)).await
}

async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if (response.status().is_client_error() || response.status().is_server_error())
        && response.extensions().get::<OAuthResponse>().is_none()
    {
        let status = response.status();
        let mut sanitized = (
            status,
            Json(json!({"error": status.canonical_reason().unwrap_or("request failed")})),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            sanitized
                .headers_mut()
                .insert("www-authenticate", "Bearer".parse().unwrap());
        }
        response = sanitized;
    }
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
    Ok(Json(json!({"status":"ok"})))
}

async fn register(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<Write<Object>>,
) -> Result<Json<Record>> {
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
    Extension(_principal): Extension<Principal>,
) -> Result<Json<Record>> {
    Ok(Json(app.store.get(&scope, "object", &id).await?))
}
async fn objects(
    State(app): State<App>,
    Path(scope): Path<String>,
    Extension(_principal): Extension<Principal>,
) -> Result<Json<Value>> {
    Ok(Json(serde_json::to_value(
        app.store.list(&scope, "object").await?,
    )?))
}
async fn graph(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<Write<Graph>>,
) -> Result<Json<Record>> {
    if let Some(connector) = &body.definition.execution_connector {
        name(connector)?;
    }
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
    Extension(_principal): Extension<Principal>,
) -> Result<Json<Record>> {
    Ok(Json(app.store.get(&scope, "graph", &id).await?))
}
async fn grants(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<Write<Grants>>,
) -> Result<Json<Record>> {
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
    Extension(_principal): Extension<Principal>,
) -> Result<Json<Record>> {
    Ok(Json(app.store.get(&scope, "grants", &id).await?))
}
async fn publish(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<Publish>,
) -> Result<Json<Manifest>> {
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
    known_revision: Option<i64>,
    #[serde(default)]
    q: String,
}

async fn resolve(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Query(read): Query<Read>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>> {
    app.authorize(&scope, &id, &principal, true).await?;
    let revision = app.store.release_revision(&scope, &id, read.revision).await?;
    if read.known_revision == Some(revision) {
        return Ok(Json(json!({"unchanged": true, "scope": scope, "graph": id, "revision": revision, "principal": principal})));
    }
    Ok(Json(serde_json::to_value(Resolved {
        manifest: app.store.release(&scope, &id, Some(revision)).await?,
        principal,
    })?))
}
async fn discover(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Query(read): Query<Read>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>> {
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
            if let Some(object) = record.definition.as_object_mut() {
                object.remove("connector");
                object.remove("iceberg");
            }
            if !format!("{id} {}", record.definition)
                .to_lowercase()
                .contains(&query)
            {
                return None;
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
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>> {
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
    Extension(_principal): Extension<Principal>,
) -> Result<Json<Value>> {
    Ok(Json(json!(app.store.audit(&scope).await?)))
}

#[derive(Clone)]
struct OAuthResponse;
async fn token(
    State(app): State<App>,
    Path(scope): Path<String>,
    headers: HeaderMap,
    payload: std::result::Result<
        Form<crate::auth::TokenRequest>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    if name(&scope).is_err() {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let Some(auth) = app.authentication.read().await.clone() else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    if !auth.token_service_enabled(&scope) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let Ok(Form(request)) = payload else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let basic = match headers.get("authorization") {
        None => None,
        Some(value) => match value.to_str().ok().and_then(|v| v.strip_prefix("Basic ")) {
            Some(value) => Some(value),
            None => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"),
        },
    };
    match auth.token(&app.store, &scope, basic, request).await {
        Ok(value) => Json(value).into_response(),
        Err(Error::Invalid(_)) => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        Err(_) => oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"),
    }
}
fn oauth_error(status: StatusCode, code: &str) -> Response {
    let mut response = (status, Json(json!({"error":code}))).into_response();
    response.extensions_mut().insert(OAuthResponse);
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert("www-authenticate", "Basic".parse().unwrap());
    }
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalRegistration {
    principal: Principal,
    #[serde(default = "principal_enabled")]
    enabled: bool,
}
fn principal_enabled() -> bool {
    true
}
async fn register_principal(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Extension(actor): Extension<Principal>,
    Json(body): Json<Write<PrincipalRegistration>>,
) -> Result<Json<Value>> {
    let secret = crate::auth::new_secret();
    let client = crate::auth::ClientRegistration {
        client_id: id.clone(),
        secret_sha256: crate::auth::fingerprint(&secret),
        principal: body.definition.principal,
        enabled: body.definition.enabled,
    };
    crate::auth::validate_client(&client)?;
    let record = app
        .store
        .put(
            &scope,
            "auth_principal",
            &id,
            body.expected_version,
            serde_json::to_value(&client)?,
            &actor.subject,
        )
        .await?;
    Ok(Json(
        json!({"version":record.version,"client_id":id,"client_secret":secret,"principal":client.principal,"enabled":client.enabled}),
    ))
}
async fn principal(
    State(app): State<App>,
    Path((scope, id)): Path<(String, String)>,
    Extension(_actor): Extension<Principal>,
) -> Result<Json<Record>> {
    Ok(Json(crate::auth::public_record(
        app.store.get(&scope, "auth_principal", &id).await?,
    )))
}
async fn principals(
    State(app): State<App>,
    Path(scope): Path<String>,
    Extension(_actor): Extension<Principal>,
) -> Result<Json<Value>> {
    let records: Vec<_> = app
        .store
        .list(&scope, "auth_principal")
        .await?
        .into_iter()
        .map(|(id, record)| (id, crate::auth::public_record(record)))
        .collect();
    Ok(Json(json!(records)))
}
