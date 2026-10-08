use reqwest::Method;
use serde::de::DeserializeOwned;
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
struct CatalogClient {
    http: reqwest::Client,
    url: String,
    token: String,
    scope: String,
}
impl CatalogClient {
    fn new(url: &str, token: String, scope: String) -> TestResult<Self> {
        Ok(Self {
            http: reqwest::Client::new(),
            url: url.into(),
            token,
            scope,
        })
    }
    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> TestResult<T> {
        let mut request = self
            .http
            .request(method, format!("{}/v1/{}/{}", self.url, self.scope, path))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            return Err(format!("{status}: {text}").into());
        }
        Ok(serde_json::from_str(&text)?)
    }
    async fn register(
        &self,
        id: &str,
        definition: Value,
        expected_version: i64,
    ) -> TestResult<Record> {
        self.request(
            Method::PUT,
            &format!("objects/{id}"),
            Some(json!({"definition":definition,"expected_version":expected_version})),
        )
        .await
    }
    async fn put_graph(
        &self,
        id: &str,
        definition: Graph,
        expected_version: i64,
    ) -> TestResult<Record> {
        self.request(
            Method::PUT,
            &format!("graphs/{id}"),
            Some(json!({"definition":definition,"expected_version":expected_version})),
        )
        .await
    }
    async fn set_grants(
        &self,
        id: &str,
        definition: Grants,
        expected_version: i64,
    ) -> TestResult<Record> {
        self.request(
            Method::PUT,
            &format!("graphs/{id}/grants"),
            Some(json!({"definition":definition,"expected_version":expected_version})),
        )
        .await
    }
    async fn publish(&self, id: &str, request: Publish) -> TestResult<Manifest> {
        self.request(
            Method::POST,
            &format!("graphs/{id}/publish"),
            Some(serde_json::to_value(request)?),
        )
        .await
    }
    async fn resolve(&self, id: &str, revision: Option<i64>) -> TestResult<Resolved> {
        self.request(
            Method::GET,
            &format!(
                "graphs/{id}/resolve{}",
                revision
                    .map(|r| format!("?revision={r}"))
                    .unwrap_or_default()
            ),
            None,
        )
        .await
    }
    async fn discover(&self, id: &str, revision: Option<i64>) -> TestResult<Value> {
        self.request(
            Method::GET,
            &format!(
                "graphs/{id}/discover{}",
                revision
                    .map(|r| format!("?revision={r}"))
                    .unwrap_or_default()
            ),
            None,
        )
        .await
    }
}
use axum::Router;
use orchid_catalog::{
    api::{App, router},
    model::*,
    store::Store,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn identities() -> Vec<Identity> {
    [
        ("admin", true, vec![]),
        ("reader", false, vec!["read"]),
        ("discoverer", false, vec!["discover"]),
        ("outsider", false, vec![]),
    ]
    .into_iter()
    .map(|(subject, admin, roles)| Identity {
        sha256: format!("{:x}", Sha256::digest(subject.as_bytes())),
        principal: Principal {
            subject: subject.into(),
            admin,
            roles: roles.into_iter().map(str::to_owned).collect(),
            tenant: Some("tenant_a".into()),
        },
    })
    .collect()
}

async fn server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, handle)
}

pub fn definitions() -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "local".into(),
            json!({"kind":"connector","description":"Host SQL connection","adapter":"duckdb","protocol_version":1}),
        ),
        (
            "people".into(),
            json!({"kind":"dataset","description":"People","table":"people","columns":[{"name":"id","data_type":"int64","nullable":false},{"name":"name","data_type":"string"}]}),
        ),
        (
            "person".into(),
            json!({"kind":"entity","description":"A person","dataset":"people","mapping":{"label":"Person","table":"people","id":"id","properties":{"name":"name"}}}),
        ),
        (
            "links".into(),
            json!({"kind":"dataset","description":"Follow links","table":"follows","columns":[{"name":"id","data_type":"int64"},{"name":"src","data_type":"int64"},{"name":"dst","data_type":"int64"}]}),
        ),
        (
            "follows".into(),
            json!({"kind":"relationship","description":"One person follows another","dataset":"links","source":"person","target":"person","mapping":{"label":"FOLLOWS","table":"follows","id":"id","source":"src","target":"dst","source_label":"Person","target_label":"Person"}}),
        ),
    ])
}

async fn scenario(database: &str) {
    let store = Store::connect(database).await.unwrap();
    let scope = format!(
        "test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let app = App::new(store.clone(), identities()).unwrap();
    let (url, server) = server(router(app)).await;
    let admin = CatalogClient::new(&url, "admin".into(), scope.clone()).unwrap();
    let reader = CatalogClient::new(&url, "reader".into(), scope.clone()).unwrap();
    let discoverer = CatalogClient::new(&url, "discoverer".into(), scope.clone()).unwrap();
    let outsider = CatalogClient::new(&url, "outsider".into(), scope.clone()).unwrap();
    for (id, definition) in definitions() {
        admin
            .register(&id, serde_json::from_value(definition).unwrap(), 0)
            .await
            .unwrap();
    }
    admin
        .put_graph(
            "social",
            Graph {
                description: "Social graph".into(),
                objects: vec!["person".into()],
                execution_connector: Some("local".into()),
            },
            0,
        )
        .await
        .unwrap();
    let versions = BTreeMap::from([
        ("local".into(), 1),
        ("people".into(), 1),
        ("person".into(), 1),
    ]);
    let first = admin
        .publish(
            "social",
            Publish {
                expected_revision: 0,
                graph_version: 1,
                object_versions: versions,
            },
        )
        .await
        .unwrap();
    assert_eq!(first.revision, 1);
    assert!(reader.resolve("social", None).await.is_err());
    admin
        .set_grants(
            "social",
            Grants {
                discover: vec!["discover".into()],
                execute: vec!["read".into()],
            },
            0,
        )
        .await
        .unwrap();
    assert!(discoverer.discover("social", None).await.is_ok());
    assert!(discoverer.resolve("social", None).await.is_err());
    assert!(outsider.discover("social", None).await.is_err());
    let old = reader.resolve("social", None).await.unwrap();
    let unchanged: Value = reader.request(Method::GET, "graphs/social/resolve?known_revision=1", None).await.unwrap();
    assert_eq!(unchanged["unchanged"], true);
    assert_eq!(unchanged["revision"], 1);
    assert_eq!(unchanged["scope"], scope);
    assert_eq!(unchanged["graph"], "social");
    assert!(unchanged.get("manifest").is_none());
    assert!(discoverer.request::<Value>(Method::GET, "graphs/social/resolve?known_revision=1", None).await.is_err());

    // Register a relationship independently, publish, then a new embedded engine sees it.
    admin
        .put_graph(
            "social",
            Graph {
                description: "Social graph with relationships".into(),
                objects: vec!["follows".into()],
                execution_connector: Some("local".into()),
            },
            1,
        )
        .await
        .unwrap();
    let versions = definitions()
        .keys()
        .map(|k| (k.clone(), 1))
        .collect::<BTreeMap<_, _>>();
    let (a, b) = tokio::join!(
        admin.publish(
            "social",
            Publish {
                expected_revision: 1,
                graph_version: 2,
                object_versions: versions.clone()
            }
        ),
        admin.publish(
            "social",
            Publish {
                expected_revision: 1,
                graph_version: 2,
                object_versions: versions.clone()
            }
        )
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one concurrent publisher wins"
    );
    let new = reader.resolve("social", None).await.unwrap();
    let changed: Value = reader.request(Method::GET, "graphs/social/resolve?known_revision=1", None).await.unwrap();
    assert_eq!(changed["manifest"]["revision"], 2);
    let pinned: Value = reader.request(Method::GET, "graphs/social/resolve?revision=1&known_revision=1", None).await.unwrap();
    assert_eq!(pinned["unchanged"], true);
    assert_eq!(pinned["revision"], 1);
    assert!(reader.request::<Value>(Method::GET, "graphs/social/resolve?revision=99&known_revision=99", None).await.is_err());

    assert_eq!(old.manifest.revision, 1);
    assert_eq!(new.manifest.revision, 2);
    assert_eq!(new.manifest.schema["edges"][0]["label"], "FOLLOWS");
    assert_eq!(old.manifest.schema["edges"], json!([]));
    // Bad endpoint types cannot replace an active release.
    let mut bad = definitions()["links"].clone();
    bad["columns"][1]["data_type"] = json!("string");
    admin
        .register("links", serde_json::from_value(bad).unwrap(), 1)
        .await
        .unwrap();
    let mut bad_versions = versions.clone();
    bad_versions.insert("links".into(), 2);
    assert!(
        admin
            .publish(
                "social",
                Publish {
                    expected_revision: 2,
                    graph_version: 2,
                    object_versions: bad_versions
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        reader
            .resolve("social", None)
            .await
            .unwrap()
            .manifest
            .revision,
        2
    );
    assert_eq!(
        reader
            .resolve("social", Some(1))
            .await
            .unwrap()
            .manifest
            .schema["edges"],
        json!([])
    );
    // ACLs are live, including reads of old releases.
    admin
        .set_grants("social", Grants::default(), 1)
        .await
        .unwrap();
    assert!(reader.resolve("social", Some(1)).await.is_err());
    assert!(reader.request::<Value>(Method::GET, "graphs/social/resolve?revision=1&known_revision=1", None).await.is_err());
    assert!(reader.discover("social", Some(1)).await.is_err());
    assert_eq!(
        store
            .audit(&scope)
            .await
            .unwrap()
            .iter()
            .filter(|e| e["action"] == "publish")
            .count(),
        2
    );
    server.abort();
    store.pool.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_catalog_contract() {
    scenario("sqlite::memory:").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_catalog_contract() {
    let Ok(url) = std::env::var("CATALOG_TEST_POSTGRES") else {
        eprintln!("Set CATALOG_TEST_POSTGRES for PostgreSQL integration tests");
        return;
    };
    scenario(&url).await;
}

#[tokio::test]
async fn authentication_and_registration_validation() {
    let app = App::new(
        Store::connect("sqlite::memory:").await.unwrap(),
        identities(),
    )
    .unwrap();
    let (url, server) = server(router(app)).await;
    let http = reqwest::Client::new();
    let path = format!("{url}/v1/test/objects/local");
    assert_eq!(http.get(&path).send().await.unwrap().status(), 401);
    assert_eq!(
        http.put(&path)
            .bearer_auth("reader")
            .json(&json!({"expected_version":0,"definition":definitions()["local"]}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let mut secret = definitions()["local"].clone();
    secret["password"] = json!("should-not-be-stored");
    assert_eq!(
        http.put(&path)
            .bearer_auth("admin")
            .json(&json!({"expected_version":0,"definition":secret}))
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    server.abort();
}

#[test]
fn schemas_and_provider_registration_remain_extensible() {
    let examples: Value =
        serde_json::from_str(include_str!("../examples/search-registrations.json")).unwrap();
    for object in examples.as_object().unwrap().values() {
        orchid_catalog::model::validate_object(object).unwrap();
    }
    let mut connector = examples["document_backend"].clone();
    connector["adapter"] = json!("future_search_provider");
    orchid_catalog::model::validate_object(&connector).unwrap();
    connector["endpoint"] = json!("https://user:secret@example.com");
    assert!(orchid_catalog::model::validate_object(&connector).is_err());
    let mut retrieval = examples["log_search"].clone();
    retrieval["collection"] = json!("logs-2026-10");
    orchid_catalog::model::validate_object(&retrieval).unwrap();
    retrieval["input_schema"] = json!({"type": 12});
    assert!(orchid_catalog::model::validate_object(&retrieval).is_err());
    retrieval.as_object_mut().unwrap().remove("input_schema");
    retrieval["max_age_seconds"] = json!(30);
    assert!(orchid_catalog::model::validate_object(&retrieval).is_err());
}

#[test]
fn structural_checks_reject_dangling_keys_and_duplicate_labels() {
    let graph = Graph {
        description: "test".into(),
        objects: vec!["follows".into()],
        execution_connector: Some("local".into()),
    };
    let mut objects = definitions();
    objects.get_mut("person").unwrap()["mapping"]["id"] = json!("missing_column");
    assert!(orchid_catalog::assembly::assemble(&graph, &objects).is_err());
    let mut objects = definitions();
    objects.insert("duplicate_person".into(), objects["person"].clone());
    assert!(orchid_catalog::assembly::assemble(&graph, &objects).is_err());
    let mut objects = definitions();
    objects.get_mut("follows").unwrap()["target"] = json!("missing_entity");
    assert!(orchid_catalog::assembly::assemble(&graph, &objects).is_err());
    let mut objects = definitions();
    objects.get_mut("follows").unwrap()["mapping"]["source"] = json!(["src", "dst"]);
    assert!(orchid_catalog::assembly::assemble(&graph, &objects).is_err());
}

#[tokio::test]
async fn sqlite_survives_restart_and_rejects_stale_draft_writes() {
    let path = std::env::temp_dir().join(format!(
        "orchid-catalog-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let store = Store::connect(&url).await.unwrap();
    store
        .put(
            "persistence",
            "object",
            "local",
            0,
            definitions()["local"].clone(),
            "admin",
        )
        .await
        .unwrap();
    assert!(
        store
            .put(
                "persistence",
                "object",
                "local",
                0,
                definitions()["local"].clone(),
                "admin"
            )
            .await
            .is_err()
    );
    store.pool.close().await;
    let reopened = Store::connect(&url).await.unwrap();
    assert_eq!(
        reopened
            .get("persistence", "object", "local")
            .await
            .unwrap()
            .version,
        1
    );
    assert_eq!(reopened.audit("persistence").await.unwrap().len(), 1);
    reopened.pool.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn identity_revocation_and_discovery_do_not_leak_connector_secrets() {
    let app = App::new(
        Store::connect("sqlite::memory:").await.unwrap(),
        identities(),
    )
    .unwrap();
    let live_identities = app.identities.clone();
    let (url, handle) = server(router(app)).await;
    let admin = CatalogClient::new(&url, "admin".into(), "discovery".into()).unwrap();
    for (id, definition) in definitions() {
        admin.register(&id, definition, 0).await.unwrap();
    }
    admin
        .put_graph(
            "social",
            Graph {
                description: "test".into(),
                objects: vec!["person".into()],
                execution_connector: Some("local".into()),
            },
            0,
        )
        .await
        .unwrap();
    let expected = ["local", "people", "person"]
        .into_iter()
        .map(|k| (k.into(), 1))
        .collect();
    admin
        .publish(
            "social",
            Publish {
                expected_revision: 0,
                graph_version: 1,
                object_versions: expected,
            },
        )
        .await
        .unwrap();
    let discovery = admin.discover("social", None).await.unwrap();
    assert!(
        discovery["objects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["definition"]["kind"] != "connector")
    );
    live_identities.write().await.clear();
    assert!(admin.resolve("social", None).await.is_err());
    handle.abort();
}

fn declarative_bundle() -> Value {
    serde_json::from_str(include_str!("../examples/declarative-relationships.json")).unwrap()
}

#[test]
fn declarative_contract_validation() {
    let bundle = declarative_bundle();
    let objects: BTreeMap<String, Value> =
        serde_json::from_value(bundle["objects"].clone()).unwrap();
    let graph: Graph = serde_json::from_value(bundle["graph"].clone()).unwrap();
    orchid_catalog::assembly::assemble(&graph, &objects).unwrap();
    let original = &objects["similar_shapes"];
    for (field, bad) in [
        ("default", json!("ten")),
        ("default", json!(0)),
        ("schema", json!({"type": "bogus"})),
        ("schema", json!({"$ref":"https://example.invalid/schema"})),
    ] {
        let mut edge = original.clone();
        edge["parameters"][0][field] = bad;
        assert!(validate_object(&edge).is_err());
    }
    let mut edge = original.clone();
    edge["parameters"][1]["name"] = json!("k");
    assert!(validate_object(&edge).is_err());
    let mut edge = original.clone();
    edge["cypher"] = json!(" \n ");
    assert!(validate_object(&edge).is_err());
    let mut edge = original.clone();
    edge["returns"]["properties"]["target"] = json!({"type":"number"});
    assert!(validate_object(&edge).is_err());
    let mut edge = original.clone();
    edge["returns"]["properties"]["score"] = json!({"type": 7});
    assert!(validate_object(&edge).is_err());
    edge["returns"]["properties"]["score"] = json!({"$ref":"https://example.invalid/schema"});
    assert!(validate_object(&edge).is_err());
    edge["returns"]["properties"]["score"] =
        json!({"$defs":{"score":{"type":"number"}},"$ref":"#/$defs/score"});
    validate_object(&edge).unwrap();
    // Function calls are opaque Cypher; there is no catalog function registry.
    edge["cypher"] = json!(
        "WITH source RETURN source AS target, future.geometry.score(source.geometry) AS score"
    );
    validate_object(&edge).unwrap();
    edge["functions"] = json!(["similar_shapes"]);
    assert!(validate_object(&edge).is_err());
    assert!(
        validate_object(&json!({"kind":"function","name":"robotics.geometry.similarity"})).is_err()
    );
    for field in ["source", "target"] {
        let mut bad = objects.clone();
        bad.get_mut("similar_shapes").unwrap()[field] = json!("shapes");
        assert!(orchid_catalog::assembly::assemble(&graph, &bad).is_err());
    }
    let mut bad = objects.clone();
    bad.get_mut("related_documents").unwrap()["name"] = json!("SIMILAR");
    assert!(orchid_catalog::assembly::assemble(&graph, &bad).is_err());
}

async fn declarative_scenario(database: &str) {
    let store = Store::connect(database).await.unwrap();
    let app = App::new(store.clone(), identities()).unwrap();
    let (url, handle) = server(router(app)).await;
    let scope = format!(
        "declarative_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let admin = CatalogClient::new(&url, "admin".into(), scope.clone()).unwrap();
    let reader = CatalogClient::new(&url, "reader".into(), scope.clone()).unwrap();
    let discoverer = CatalogClient::new(&url, "discoverer".into(), scope).unwrap();
    let bundle = declarative_bundle();
    let mut versions = BTreeMap::new();
    for (id, definition) in bundle["objects"].as_object().unwrap() {
        let record = admin.register(id, definition.clone(), 0).await.unwrap();
        versions.insert(id.clone(), record.version);
    }
    admin
        .put_graph(
            "knowledge",
            serde_json::from_value(bundle["graph"].clone()).unwrap(),
            0,
        )
        .await
        .unwrap();
    let publish_request = |versions: BTreeMap<String, i64>, revision| Publish {
        expected_revision: revision,
        graph_version: 1,
        object_versions: versions,
    };
    let mut incomplete = versions.clone();
    incomplete.remove("shape");
    assert!(
        admin
            .publish("knowledge", publish_request(incomplete, 0))
            .await
            .is_err()
    );
    let first = admin
        .publish("knowledge", publish_request(versions.clone(), 0))
        .await
        .unwrap();
    assert_eq!(first.protocol_version, 2);
    assert_eq!(
        first.objects.len(),
        bundle["objects"].as_object().unwrap().len()
    );
    assert!(first.schema["engines"].as_object().unwrap().is_empty());
    for (id, definition) in bundle["objects"].as_object().unwrap() {
        assert_eq!(&first.objects[id].definition, definition);
    }
    admin
        .set_grants(
            "knowledge",
            Grants {
                discover: vec!["discover".into()],
                execute: vec!["read".into()],
            },
            0,
        )
        .await
        .unwrap();
    let discovered = discoverer.discover("knowledge", None).await.unwrap();
    assert!(
        discovered["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["definition"]["cypher"] == bundle["objects"]["similar_shapes"]["cypher"])
    );
    assert!(discoverer.resolve("knowledge", None).await.is_err());
    let mut updated = bundle["objects"]["similar_shapes"].clone();
    updated["description"] = json!("Updated contract description");
    admin
        .register("similar_shapes", updated.clone(), 1)
        .await
        .unwrap();
    assert!(
        admin
            .publish("knowledge", publish_request(versions.clone(), 1))
            .await
            .is_err()
    );
    assert_eq!(
        reader
            .resolve("knowledge", None)
            .await
            .unwrap()
            .manifest
            .revision,
        1
    );
    versions.insert("similar_shapes".into(), 2);
    admin
        .publish("knowledge", publish_request(versions.clone(), 1))
        .await
        .unwrap();
    assert_eq!(
        reader
            .resolve("knowledge", None)
            .await
            .unwrap()
            .manifest
            .objects["similar_shapes"]
            .definition,
        updated
    );
    assert_eq!(
        reader
            .resolve("knowledge", Some(1))
            .await
            .unwrap()
            .manifest
            .objects["similar_shapes"]
            .definition,
        bundle["objects"]["similar_shapes"]
    );
    let mut bad = bundle["objects"]["similar_shapes"].clone();
    bad["target"] = json!("shapes");
    admin.register("similar_shapes", bad, 2).await.unwrap();
    // Exact reviewed versions cannot publish a wrong-kind entity reference.
    versions.insert("similar_shapes".into(), 3);
    assert!(
        admin
            .publish("knowledge", publish_request(versions, 2))
            .await
            .is_err()
    );
    assert_eq!(
        reader
            .resolve("knowledge", None)
            .await
            .unwrap()
            .manifest
            .revision,
        2
    );
    admin
        .set_grants("knowledge", Grants::default(), 1)
        .await
        .unwrap();
    assert!(reader.resolve("knowledge", Some(1)).await.is_err());
    assert!(discoverer.discover("knowledge", Some(1)).await.is_err());
    handle.abort();
    store.pool.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_declarative_relationships() {
    declarative_scenario("sqlite::memory:").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_declarative_relationships() {
    if let Ok(url) = std::env::var("CATALOG_TEST_POSTGRES") {
        declarative_scenario(&url).await;
    } else {
        eprintln!("Set CATALOG_TEST_POSTGRES for PostgreSQL integration tests");
    }
}
