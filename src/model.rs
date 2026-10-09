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

pub fn principal_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(|c| c.is_control() || c == '/') {
        return Err(invalid("principal IDs require 1..256 bytes without slashes or control characters"));
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
    if value["kind"] == "cypher_relationship" {
        let mut names = std::collections::BTreeSet::new();
        for parameter in value["parameters"].as_array().unwrap() {
            let parameter_name = parameter["name"].as_str().unwrap();
            if !names.insert(parameter_name) {
                return Err(invalid("duplicate parameter name"));
            }
            let schema = &parameter["schema"];
            jsonschema::meta::validate(schema)
                .map_err(|_| invalid("parameter schema is not a valid JSON Schema"))?;
            // Only local references: registration must never fetch a schema from a network.
            let validator = jsonschema::options()
                .with_retriever(LocalSchemasOnly)
                .build(schema)
                .map_err(|_| invalid("parameter schema must be self-contained and valid"))?;
            if let Some(default) = parameter.get("default") {
                validator
                    .validate(default)
                    .map_err(|_| invalid(format!("invalid default for {parameter_name}")))?;
            }
        }
        if value["cypher"].as_str().unwrap().trim().is_empty() {
            return Err(invalid("Cypher body must not be blank"));
        }
        let target = value["returns"]["target"].as_str().unwrap();
        for (column, schema) in value["returns"]["properties"].as_object().unwrap() {
            if column == target {
                return Err(invalid("target column cannot also be an edge property"));
            }
            validate_contract_schema(schema)?;
        }
    }
    Ok(())
}

struct LocalSchemasOnly;
impl jsonschema::Retrieve for LocalSchemasOnly {
    fn retrieve(
        &self,
        _: &jsonschema::Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("external schema references are not supported".into())
    }
}

fn validate_contract_schema(schema: &Value) -> Result<()> {
    jsonschema::meta::validate(schema)
        .map_err(|_| invalid("return schema is not a valid JSON Schema"))?;
    jsonschema::options()
        .with_retriever(LocalSchemasOnly)
        .build(schema)
        .map_err(|_| invalid("return schema must be self-contained and valid"))?;
    Ok(())
}

pub fn dependencies(object: &Value) -> Vec<String> {
    let fields: &[&str] = match object["kind"].as_str() {
        Some("dataset") => &["connector"],
        Some("entity") => &["dataset"],
        Some("relationship") => &["dataset", "source", "target"],
        Some("computed_relationship" | "cypher_relationship") => &["source", "target"],
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_connector: Option<String>,
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

#[cfg(test)]
mod native_type_tests {
    #[test]
    fn preserves_nested_engine_types() {
        for ty in ["list:string", r#"struct:{"id":"string","count":"int64"}"#, "json", "binary"] {
            super::validate_object(&serde_json::json!({"kind":"dataset","description":"Typed rows","table":"typed_rows","columns":[{"name":"value","data_type":ty}]})).unwrap();
        }
        assert!(super::validate_object(&serde_json::json!({"kind":"dataset","description":"Invalid","table":"typed_rows","columns":[{"name":"value","data_type":""}]})).is_err());
    }
}
