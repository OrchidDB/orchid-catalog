use crate::{Result, error::invalid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::OnceLock};

pub type Object = Value;
pub const OBJECT_SCHEMA: &str = include_str!("../schemas/object.json");

pub fn name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
    {
        return Err(invalid(
            "names must be identifiers of 1..128 ASCII characters",
        ));
    }
    Ok(())
}

pub fn validate_object(value: &Value) -> Result<()> {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    let validator = VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(OBJECT_SCHEMA).expect("checked-in schema JSON");
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .expect("checked-in schema is valid")
    });
    validator.validate(value).map_err(|e| {
        invalid(format!(
            "object fails catalog JSON Schema at {}",
            e.instance_path
        ))
    })?;
    if value["kind"] == "connector"
        && let Some(endpoint) = value.get("endpoint").and_then(Value::as_str)
    {
        let url = url::Url::parse(endpoint).map_err(|_| invalid("invalid connector endpoint"))?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        {
            return Err(invalid(
                "connector endpoints require HTTPS except on loopback, without embedded credentials/query/fragment",
            ));
        }
    }
    if value["kind"] == "retrieval"
        && value.get("max_age_seconds").is_some()
        && value.get("indexed_at").is_none()
    {
        return Err(invalid("freshness bound requires indexed_at"));
    }
    for field in ["input_schema", "output_schema"] {
        if let Some(schema) = value.get(field) {
            jsonschema::meta::validate(schema)
                .map_err(|_| invalid(format!("{field} is not a valid JSON Schema")))?;
        }
    }
    Ok(())
}

pub fn dependencies(object: &Value) -> Vec<String> {
    let fields: &[&str] = match object["kind"].as_str() {
        Some("dataset") => &["connector"],
        Some("entity") => &["dataset"],
        Some("relationship") => &["dataset", "source", "target"],
        Some("computed_relationship") => &["source", "target"],
        Some("retrieval") => &["target", "connector"],
        _ => &[],
    };
    let mut result: Vec<String> = fields
        .iter()
        .filter_map(|key| object[*key].as_str().map(str::to_owned))
        .collect();
    if let Some(owner) = object["source_metadata"]["options"]["engine"].as_str() {
        result.push(owner.into());
    }
    if let Some(indexes) = object["source_metadata"]["indexes"].as_array() {
        for index in indexes {
            if let Some(owner) = index["options"]["engine"].as_str() {
                result.push(owner.into());
            }
        }
    }
    result
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    pub description: String,
    pub objects: Vec<String>,
    pub execution_connector: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Write<T> {
    pub expected_version: i64,
    pub definition: T,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub version: i64,
    pub definition: Value,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publish {
    pub expected_revision: i64,
    pub graph_version: i64,
    pub object_versions: BTreeMap<String, i64>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    pub discover: Vec<String>,
    pub execute: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub subject: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub tenant: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub sha256: String,
    pub principal: Principal,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub protocol_version: u32,
    pub scope: String,
    pub graph: String,
    pub revision: i64,
    pub graph_version: i64,
    pub description: String,
    pub published_at: chrono::DateTime<chrono::Utc>,
    pub objects: BTreeMap<String, Record>,
    pub schema: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolved {
    pub manifest: Manifest,
    pub principal: Principal,
}
