//! cargo run --example register -- examples/social.json
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "examples/social.json".into());
    let bundle: Value = serde_json::from_slice(&tokio::fs::read(file).await?)?;
    let endpoint = std::env::var("CATALOG_URL").unwrap_or_else(|_| "http://127.0.0.1:8182".into());
    let scope = std::env::var("CATALOG_SCOPE").unwrap_or_else(|_| "demo".into());
    orchid_catalog::model::name(&scope)?;
    let token = std::env::var("CATALOG_TOKEN")?;
    let http = reqwest::Client::new();
    let base = format!("{}/v1/{scope}", endpoint.trim_end_matches('/'));
    let graph_id = bundle["graph_id"].as_str().unwrap_or("social");
    orchid_catalog::model::name(graph_id)?;
    let mut versions = serde_json::Map::new();
    for (name, definition) in bundle["objects"].as_object().ok_or("objects required")? {
        let response: Value = http
            .put(format!("{base}/objects/{name}"))
            .bearer_auth(&token)
            .json(&json!({"expected_version":0,"definition":definition}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        versions.insert(name.clone(), response["version"].clone());
    }
    let graph: Value = http
        .put(format!("{base}/graphs/{graph_id}"))
        .bearer_auth(&token)
        .json(&json!({"expected_version":0,"definition":bundle["graph"]}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let published: Value = http.post(format!("{base}/graphs/{graph_id}/publish")).bearer_auth(&token)
        .json(&json!({"expected_revision":0,"graph_version":graph["version"],"object_versions":versions}))
        .send().await?.error_for_status()?.json().await?;
    println!("Published {graph_id} revision {}", published["revision"]);
    Ok(())
}
