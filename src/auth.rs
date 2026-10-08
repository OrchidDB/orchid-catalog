use crate::{
    Error, Result,
    error::invalid,
    model::{Principal, Record, name},
    store::Store,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    jwk::JwkSet,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub default: PolicyConfig,
    #[serde(default)]
    pub scopes: BTreeMap<String, PolicyConfig>,
}
#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Internal,
    External,
    Mixed,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub mode: Mode,
    pub internal: Option<InternalConfig>,
    pub external: Option<ExternalConfig>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalConfig {
    pub issuer: String,
    pub audience: String,
    pub signing: Signing,
    #[serde(default = "lifetime")]
    pub token_lifetime_seconds: u64,
    #[serde(default)]
    pub clients: Vec<ClientRegistration>,
}
fn lifetime() -> u64 {
    3600
}
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Signing {
    Symmetric {
        key_file: String,
    },
    Rsa {
        private_key_file: String,
        public_key_file: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRegistration {
    pub client_id: String,
    pub secret_sha256: String,
    pub principal: Principal,
    #[serde(default = "enabled")]
    pub enabled: bool,
}
fn enabled() -> bool {
    true
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: Option<String>,
    pub introspection: Option<Introspection>,
    #[serde(default = "subject_claim")]
    pub subject_claim: String,
    pub name_claim: Option<String>,
    #[serde(default = "roles_claim")]
    pub roles_claim: String,
    pub tenant_claim: Option<String>,
    #[serde(default)]
    pub role_mappings: Vec<RoleMapping>,
    pub role_filter: Option<String>,
    #[serde(default)]
    pub admin_roles: Vec<String>,
    #[serde(default = "enabled")]
    pub require_registered_principal: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Introspection {
    pub endpoint: String,
    pub client_id: String,
    pub client_secret_env: String,
}
fn subject_claim() -> String {
    "sub".into()
}
fn roles_claim() -> String {
    "roles".into()
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMapping {
    pub regex: String,
    pub replacement: String,
}
struct Internal {
    config: InternalConfig,
    encoding: EncodingKey,
    decoding: DecodingKey,
    algorithm: Algorithm,
}
struct External {
    config: ExternalConfig,
    client: reqwest::Client,
    keys: Mutex<Option<(Instant, JwkSet)>>,
    filter: Option<Regex>,
    mappings: Vec<(Regex, String)>,
}
struct Policy {
    mode: Mode,
    internal: Option<Internal>,
    external: Option<External>,
}
pub struct Authenticator {
    default: Arc<Policy>,
    scopes: BTreeMap<String, Arc<Policy>>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
    catalog_scope: String,
    generation: String,
    roles: Vec<String>,
    admin: bool,
}
#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub resource: Option<String>,
    pub audience: Option<String>,
}

impl Authenticator {
    pub async fn load(config: AuthConfig) -> Result<Self> {
        let default = Arc::new(Policy::load(config.default).await?);
        let mut scopes = BTreeMap::new();
        for (scope, config) in config.scopes {
            name(&scope)?;
            scopes.insert(scope, Arc::new(Policy::load(config).await?));
        }
        Ok(Self { default, scopes })
    }
    fn policy(&self, scope: &str) -> &Policy {
        self.scopes.get(scope).unwrap_or(&self.default)
    }
    pub async fn authenticate(&self, store: &Store, scope: &str, token: &str) -> Result<Principal> {
        let policy = self.policy(scope);
        if policy.mode != Mode::External {
            if let Some(internal) = &policy.internal {
                if let Ok((principal, _)) = internal.verify(store, scope, token).await {
                    return Ok(principal);
                }
                if unverified_issuer(token).as_deref() == Some(&internal.config.issuer) {
                    return Err(Error::Unauthorized);
                }
            }
        }
        if policy.mode != Mode::Internal {
            if let Some(external) = &policy.external {
                return external.verify(store, scope, token).await;
            }
        }
        Err(Error::Unauthorized)
    }
    pub fn token_service_enabled(&self, scope: &str) -> bool {
        self.policy(scope).mode != Mode::External
    }
    pub async fn token(
        &self,
        store: &Store,
        scope: &str,
        basic: Option<&str>,
        request: TokenRequest,
    ) -> Result<Value> {
        let policy = self.policy(scope);
        let internal = policy
            .internal
            .as_ref()
            .filter(|_| policy.mode != Mode::External)
            .ok_or(Error::Unauthorized)?;
        let (mut principal, client, inherited) = match request.grant_type.as_str() {
            "client_credentials" => {
                let (id, secret) = if let Some(basic) = basic {
                    if request.client_id.is_some() || request.client_secret.is_some() {
                        return Err(Error::Unauthorized);
                    }
                    let decoded = STANDARD.decode(basic).map_err(|_| Error::Unauthorized)?;
                    let decoded = String::from_utf8(decoded).map_err(|_| Error::Unauthorized)?;
                    let (id, secret) = decoded.split_once(':').ok_or(Error::Unauthorized)?;
                    (decode_form_component(id)?, decode_form_component(secret)?)
                } else {
                    (
                        request.client_id.ok_or(Error::Unauthorized)?,
                        request.client_secret.ok_or(Error::Unauthorized)?,
                    )
                };
                let client = internal.client(store, scope, &id).await?;
                let digest = fingerprint(&secret);
                if !bool::from(digest.as_bytes().ct_eq(client.secret_sha256.as_bytes())) {
                    return Err(Error::Unauthorized);
                }
                (client.principal.clone(), client, None)
            }
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                if basic.is_some()
                    || request.client_id.is_some()
                    || request.client_secret.is_some()
                    || request.actor_token.is_some()
                    || request.resource.is_some()
                    || request
                        .audience
                        .as_ref()
                        .is_some_and(|v| v != &internal.config.audience)
                    || !matches!(
                        request.subject_token_type.as_deref(),
                        Some(
                            "urn:ietf:params:oauth:token-type:access_token"
                                | "urn:ietf:params:oauth:token-type:jwt"
                        )
                    )
                    || request
                        .requested_token_type
                        .as_deref()
                        .is_some_and(|v| v != "urn:ietf:params:oauth:token-type:access_token")
                {
                    return Err(Error::Unauthorized);
                }
                let token = request.subject_token.ok_or(Error::Unauthorized)?;
                let (principal, claims) = internal.verify(store, scope, &token).await?;
                let client = internal.client(store, scope, &claims.sub).await?;
                (principal, client, Some(claims))
            }
            _ => return Err(invalid("unsupported_grant_type")),
        };
        select_roles(&mut principal, request.scope.as_deref())?;
        if let Some(claims) = inherited {
            if principal.roles.iter().any(|r| !claims.roles.contains(r))
                || (principal.admin && !claims.admin)
            {
                return Err(Error::Unauthorized);
            }
        }
        let now = now();
        let claims = Claims {
            iss: internal.config.issuer.clone(),
            aud: internal.config.audience.clone(),
            sub: client.client_id,
            exp: now + internal.config.token_lifetime_seconds,
            iat: now,
            catalog_scope: scope.into(),
            generation: fingerprint(&client.secret_sha256),
            roles: principal.roles,
            admin: principal.admin,
        };
        let token = encode(
            &Header::new(internal.algorithm),
            &claims,
            &internal.encoding,
        )
        .map_err(|_| Error::Internal("token signing failed".into()))?;
        Ok(
            json!({"access_token":token,"token_type":"Bearer","expires_in":internal.config.token_lifetime_seconds,
            "issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}),
        )
    }
}
impl Policy {
    async fn load(config: PolicyConfig) -> Result<Self> {
        if config.mode != Mode::External && config.internal.is_none()
            || config.mode != Mode::Internal && config.external.is_none()
        {
            return Err(invalid("authentication configuration is incomplete"));
        }
        let internal = if let Some(config) = config.internal {
            if config.issuer.is_empty()
                || config.audience.is_empty()
                || config.token_lifetime_seconds == 0
                || config.token_lifetime_seconds > i64::MAX as u64 - now()
            {
                return Err(invalid("invalid token issuer configuration"));
            }
            let mut ids = std::collections::BTreeSet::new();
            for client in &config.clients {
                validate_client(client)?;
                if !ids.insert(&client.client_id) {
                    return Err(invalid("duplicate client"));
                }
            }
            let (encoding, decoding, algorithm) = match &config.signing {
                Signing::Symmetric { key_file } => {
                    let key = read_key(key_file).await?;
                    if key.len() < 32 {
                        return Err(invalid("signing key requires at least 32 bytes"));
                    }
                    (
                        EncodingKey::from_secret(&key),
                        DecodingKey::from_secret(&key),
                        Algorithm::HS256,
                    )
                }
                Signing::Rsa {
                    private_key_file,
                    public_key_file,
                } => {
                    let private = read_key(private_key_file).await?;
                    let public = read_key(public_key_file).await?;
                    (
                        EncodingKey::from_rsa_pem(&private)
                            .map_err(|_| invalid("invalid signing key"))?,
                        DecodingKey::from_rsa_pem(&public)
                            .map_err(|_| invalid("invalid verification key"))?,
                        Algorithm::RS256,
                    )
                }
            };
            let probe = json!({"exp":now()+60,"iss":config.issuer,"aud":config.audience});
            let token = encode(&Header::new(algorithm), &probe, &encoding)
                .map_err(|_| invalid("invalid signing key"))?;
            decode::<Value>(
                &token,
                &decoding,
                &validation(algorithm, &config.issuer, &config.audience),
            )
            .map_err(|_| invalid("signing keys do not match"))?;
            Some(Internal {
                config,
                encoding,
                decoding,
                algorithm,
            })
        } else {
            None
        };
        let external = if let Some(mut config) = config.external {
            secure_url(&config.issuer)?;
            if config.audience.is_empty() || config.subject_claim.is_empty() {
                return Err(invalid("invalid OIDC configuration"));
            }
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()
                .map_err(|_| invalid("OIDC transport configuration failed"))?;
            if config.jwks_uri.is_none() && config.introspection.is_none() {
                let metadata: Value = client
                    .get(format!(
                        "{}/.well-known/openid-configuration",
                        config.issuer.trim_end_matches('/')
                    ))
                    .send()
                    .await
                    .map_err(|_| invalid("OIDC discovery failed"))?
                    .error_for_status()
                    .map_err(|_| invalid("OIDC discovery failed"))?
                    .json()
                    .await
                    .map_err(|_| invalid("invalid OIDC discovery response"))?;
                if metadata["issuer"].as_str() != Some(&config.issuer) {
                    return Err(invalid("OIDC issuer mismatch"));
                }
                config.jwks_uri = Some(
                    metadata["jwks_uri"]
                        .as_str()
                        .ok_or_else(|| invalid("OIDC keys endpoint missing"))?
                        .into(),
                );
            }
            if let Some(uri) = &config.jwks_uri {
                secure_url(uri)?;
            }
            if let Some(introspection) = &config.introspection {
                secure_url(&introspection.endpoint)?;
                if introspection.client_id.is_empty() || introspection.client_secret_env.is_empty()
                {
                    return Err(invalid("invalid OIDC introspection configuration"));
                }
            }
            let filter = config
                .role_filter
                .as_ref()
                .map(|v| Regex::new(v).map_err(|_| invalid("invalid role filter")))
                .transpose()?;
            let mappings = config
                .role_mappings
                .iter()
                .map(|v| {
                    Ok((
                        Regex::new(&v.regex).map_err(|_| invalid("invalid role mapping"))?,
                        v.replacement.clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            Some(External {
                config,
                client,
                keys: Mutex::new(None),
                filter,
                mappings,
            })
        } else {
            None
        };
        Ok(Self {
            mode: config.mode,
            internal,
            external,
        })
    }
}
impl Internal {
    async fn client(&self, store: &Store, scope: &str, id: &str) -> Result<ClientRegistration> {
        let client = match store.get(scope, "auth_principal", id).await {
            Ok(record) => {
                serde_json::from_value(record.definition).map_err(|_| Error::Unauthorized)?
            }
            Err(Error::NotFound) => self
                .config
                .clients
                .iter()
                .find(|c| c.client_id == id)
                .cloned()
                .ok_or(Error::Unauthorized)?,
            Err(_) => return Err(Error::Unauthorized),
        };
        if !client.enabled {
            return Err(Error::Unauthorized);
        }
        Ok(client)
    }
    async fn verify(&self, store: &Store, scope: &str, token: &str) -> Result<(Principal, Claims)> {
        let claims = decode::<Claims>(
            token,
            &self.decoding,
            &validation(self.algorithm, &self.config.issuer, &self.config.audience),
        )
        .map_err(|_| Error::Unauthorized)?
        .claims;
        if claims.catalog_scope != scope || claims.iat > now() {
            return Err(Error::Unauthorized);
        }
        let client = self.client(store, scope, &claims.sub).await?;
        if !bool::from(
            claims
                .generation
                .as_bytes()
                .ct_eq(fingerprint(&client.secret_sha256).as_bytes()),
        ) {
            return Err(Error::Unauthorized);
        }
        let mut principal = client.principal;
        principal.roles.retain(|r| claims.roles.contains(r));
        principal.admin &= claims.admin;
        Ok((principal, claims))
    }
}
impl External {
    async fn verify(&self, store: &Store, scope: &str, token: &str) -> Result<Principal> {
        let claims = if let Some(introspection) = &self.config.introspection {
            if unverified_issuer(token).is_some_and(|issuer| issuer != self.config.issuer) {
                return Err(Error::Unauthorized);
            }
            let secret =
                std::env::var(&introspection.client_secret_env).map_err(|_| Error::Unauthorized)?;
            if secret.is_empty() {
                return Err(Error::Unauthorized);
            }
            let claims: Value = self
                .client
                .post(&introspection.endpoint)
                .basic_auth(&introspection.client_id, Some(secret))
                .form(&[("token", token), ("token_type_hint", "access_token")])
                .send()
                .await
                .map_err(|_| Error::Unauthorized)?
                .error_for_status()
                .map_err(|_| Error::Unauthorized)?
                .json()
                .await
                .map_err(|_| Error::Unauthorized)?;
            let audience = &claims["aud"];
            let valid_audience = audience.as_str().is_some_and(|v| v == self.config.audience)
                || audience
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(&self.config.audience)));
            if claims["active"] != true
                || claims["iss"].as_str() != Some(&self.config.issuer)
                || !valid_audience
                || !claims["exp"].as_u64().is_some_and(|exp| exp > now())
                || claims
                    .get("nbf")
                    .is_some_and(|v| !v.as_u64().is_some_and(|nbf| nbf <= now()))
            {
                return Err(Error::Unauthorized);
            }
            claims
        } else {
            self.jwt_claims(token).await?
        };
        self.map_principal(store, scope, claims).await
    }
    async fn jwt_claims(&self, token: &str) -> Result<Value> {
        let header = decode_header(token).map_err(|_| Error::Unauthorized)?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::ES256
                | Algorithm::ES384
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
                | Algorithm::EdDSA
        ) {
            return Err(Error::Unauthorized);
        }
        let mut cached = self.keys.lock().await;
        let kid = header.kid.as_deref().ok_or(Error::Unauthorized)?;
        let refresh = cached.as_ref().is_none_or(|(at, keys)| {
            at.elapsed() > Duration::from_secs(300)
                || (keys.find(kid).is_none() && at.elapsed() > Duration::from_secs(5))
        });
        if refresh {
            let keys: JwkSet = self
                .client
                .get(self.config.jwks_uri.as_ref().unwrap())
                .send()
                .await
                .map_err(|_| Error::Unauthorized)?
                .error_for_status()
                .map_err(|_| Error::Unauthorized)?
                .json()
                .await
                .map_err(|_| Error::Unauthorized)?;
            *cached = Some((Instant::now(), keys));
        }
        let verify = |keys: &JwkSet| -> Result<Value> {
            if keys
                .keys
                .iter()
                .filter(|k| k.common.key_id.as_deref() == Some(kid))
                .count()
                != 1
            {
                return Err(Error::Unauthorized);
            }
            let jwk = keys.find(kid).ok_or(Error::Unauthorized)?;
            if jwk
                .common
                .key_algorithm
                .is_some_and(|alg| format!("{alg:?}") != format!("{:?}", header.alg))
                || jwk
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| *usage != jsonwebtoken::jwk::PublicKeyUse::Signature)
                || jwk
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|ops| !ops.contains(&jsonwebtoken::jwk::KeyOperations::Verify))
            {
                return Err(Error::Unauthorized);
            }
            let key = DecodingKey::from_jwk(jwk).map_err(|_| Error::Unauthorized)?;
            Ok(decode::<Value>(
                token,
                &key,
                &validation(header.alg, &self.config.issuer, &self.config.audience),
            )
            .map_err(|_| Error::Unauthorized)?
            .claims)
        };
        let result = verify(&cached.as_ref().ok_or(Error::Unauthorized)?.1);
        if result.is_err()
            && cached
                .as_ref()
                .is_some_and(|(at, _)| at.elapsed() > Duration::from_secs(5))
        {
            let keys: JwkSet = self
                .client
                .get(self.config.jwks_uri.as_ref().unwrap())
                .send()
                .await
                .map_err(|_| Error::Unauthorized)?
                .error_for_status()
                .map_err(|_| Error::Unauthorized)?
                .json()
                .await
                .map_err(|_| Error::Unauthorized)?;
            *cached = Some((Instant::now(), keys));
            return verify(&cached.as_ref().unwrap().1);
        }
        result
    }
    async fn map_principal(&self, store: &Store, scope: &str, claims: Value) -> Result<Principal> {
        let subject = claim(&claims, &self.config.subject_claim)
            .and_then(claim_text)
            .filter(|s| !s.is_empty())
            .ok_or(Error::Unauthorized)?;
        let display_name = self
            .config
            .name_claim
            .as_ref()
            .map(|path| {
                claim(&claims, path)
                    .and_then(claim_text)
                    .filter(|s| !s.is_empty())
                    .ok_or(Error::Unauthorized)
            })
            .transpose()?
            .unwrap_or_else(|| subject.clone());
        let role_claim = claim(&claims, &self.config.roles_claim);
        let raw = match role_claim {
            None => Vec::new(),
            Some(Value::String(roles)) => roles.split_whitespace().map(str::to_owned).collect(),
            Some(Value::Array(roles)) => roles
                .iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Unauthorized))
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(Error::Unauthorized),
        };
        let mut roles = Vec::new();
        for raw in raw {
            if self.filter.as_ref().is_some_and(|f| !f.is_match(&raw)) {
                continue;
            }
            let mapped = self
                .mappings
                .iter()
                .find(|(r, _)| r.is_match(&raw))
                .map(|(r, to)| r.replace(&raw, to).into_owned())
                .unwrap_or(raw);
            let role = mapped.strip_prefix("PRINCIPAL_ROLE:").unwrap_or(&mapped);
            name(role).map_err(|_| Error::Unauthorized)?;
            roles.push(role.to_owned());
        }
        roles.sort();
        roles.dedup();
        let mut principal = Principal {
            subject: display_name,
            admin: roles.iter().any(|r| self.config.admin_roles.contains(r)),
            roles,
            tenant: self
                .config
                .tenant_claim
                .as_ref()
                .and_then(|p| claim(&claims, p))
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        if self.config.require_registered_principal {
            let record = store
                .get(scope, "auth_principal", &subject)
                .await
                .map_err(|_| Error::Unauthorized)?;
            let registered: ClientRegistration =
                serde_json::from_value(record.definition).map_err(|_| Error::Unauthorized)?;
            if !registered.enabled {
                return Err(Error::Unauthorized);
            }
            principal
                .roles
                .retain(|r| registered.principal.roles.contains(r));
            principal.admin &= registered.principal.admin;
            principal.tenant = registered.principal.tenant;
        }
        Ok(principal)
    }
}
pub fn validate_client(client: &ClientRegistration) -> Result<()> {
    crate::model::principal_id(&client.client_id)?;
    if client.principal.subject.is_empty()
        || client.secret_sha256.len() != 64
        || !client
            .secret_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid client registration"));
    }
    for role in &client.principal.roles {
        name(role)?;
    }
    Ok(())
}
pub fn public_record(mut record: Record) -> Record {
    if let Some(object) = record.definition.as_object_mut() {
        object.remove("secret_sha256");
    }
    record
}
pub fn fingerprint(secret: &str) -> String {
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}
pub fn new_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}
fn validation(algorithm: Algorithm, issuer: &str, audience: &str) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_nbf = true;
    validation.leeway = 0;
    validation
}
fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims["iss"].as_str().map(str::to_owned)
}
fn claim_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}
fn claim<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('/')
        .try_fold(value, |value, part| value.get(part))
}
fn select_roles(principal: &mut Principal, scope: Option<&str>) -> Result<()> {
    let scope = scope.unwrap_or("");
    if scope == "PRINCIPAL_ROLE:ALL" {
        return Ok(());
    }
    let selected = scope
        .split_whitespace()
        .map(|r| r.strip_prefix("PRINCIPAL_ROLE:").ok_or(Error::Unauthorized))
        .collect::<Result<Vec<_>>>()?;
    if selected.iter().any(|r| {
        !principal.roles.iter().any(|p| p == r) && !(*r == "service_admin" && principal.admin)
    }) {
        return Err(Error::Unauthorized);
    }
    principal.roles.retain(|r| selected.contains(&r.as_str()));
    principal.admin &= selected.contains(&"service_admin");
    Ok(())
}
async fn read_key(path: &str) -> Result<Vec<u8>> {
    tokio::fs::read(path)
        .await
        .map_err(|_| invalid("authentication key could not be read"))
}
fn decode_form_component(value: &str) -> Result<String> {
    let input = format!("v={value}");
    url::form_urlencoded::parse(input.as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .ok_or(Error::Unauthorized)
}
fn secure_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| invalid("invalid authentication URL"))?;
    let loopback = url.host_str().is_some_and(|h| {
        h.eq_ignore_ascii_case("localhost")
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "authentication URLs require HTTPS except on loopback",
        ));
    }
    Ok(())
}
