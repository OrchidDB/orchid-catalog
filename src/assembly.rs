//! Structural validation and JSON assembly. Expression binding belongs to the engine.
use crate::{
    Result,
    error::invalid,
    model::{Graph, Object, validate_object},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn object<'a>(objects: &'a BTreeMap<String, Object>, id: &str, kind: &str) -> Result<&'a Value> {
    objects
        .get(id)
        .filter(|v| v["kind"] == kind)
        .ok_or_else(|| invalid(format!("{id}: expected {kind}")))
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| invalid(format!("missing {key}")))
}
fn keys(value: &Value) -> Result<Vec<&str>> {
    if let Some(key) = value.as_str() {
        return Ok(vec![key]);
    }
    value
        .as_array()
        .ok_or_else(|| invalid("key must be a name or list"))?
        .iter()
        .map(|v| v.as_str().ok_or_else(|| invalid("key must be a name")))
        .collect()
}
fn column_types(dataset: &Value, columns: &Value) -> Result<Vec<String>> {
    keys(columns)?
        .into_iter()
        .map(|key| {
            dataset["columns"]
                .as_array()
                .and_then(|columns| columns.iter().find(|c| c["name"] == key))
                .and_then(|c| c["data_type"].as_str())
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("unknown column {key}")))
        })
        .collect()
}
fn properties(dataset: &Value, mapping: &Value) -> Result<()> {
    if let Some(props) = mapping["properties"].as_object() {
        for column in props.values() {
            column_types(dataset, column)?;
        }
    }
    Ok(())
}

pub fn assemble(graph: &Graph, objects: &BTreeMap<String, Object>) -> Result<Value> {
    let target = object(objects, &graph.execution_connector, "connector")?;
    let mut engines = BTreeMap::from([(
        graph.execution_connector.clone(),
        json!({"dialect":target["adapter"]}),
    )]);
    let mut tables = Vec::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut computed = Vec::new();
    let mut metadata = Vec::new();
    let mut table_names = BTreeSet::new();
    let mut labels = BTreeSet::new();
    let mut edge_labels = BTreeSet::new();
    for (id, definition) in objects {
        validate_object(definition)?;
        match text(definition, "kind")? {
            "dataset" => {
                let table = text(definition, "table")?;
                if !table_names.insert(table) {
                    return Err(invalid("duplicate table mapping"));
                }
                let mut column_names = BTreeSet::new();
                let mut columns = Vec::new();
                for column in definition["columns"].as_array().unwrap() {
                    if !column_names.insert(text(column, "name")?) {
                        return Err(invalid("duplicate column"));
                    }
                    columns.push(json!({"name":column["name"],"data_type":column["data_type"],"nullable":column.get("nullable").cloned().unwrap_or(json!(true))}));
                }
                if definition.get("iceberg").is_some() {
                    let mut field_ids = BTreeSet::new();
                    for column in definition["columns"].as_array().unwrap() {
                        let field_id = column["field_id"]
                            .as_i64()
                            .ok_or_else(|| invalid("Iceberg columns require field_id"))?;
                        if !field_ids.insert(field_id) {
                            return Err(invalid("duplicate Iceberg field ID"));
                        }
                    }
                }
                let owner = definition["connector"]
                    .as_str()
                    .unwrap_or(&graph.execution_connector);
                let connector = object(objects, owner, "connector")?;
                engines.insert(owner.into(), json!({"dialect":connector["adapter"]}));
                tables.push(json!({"name":table,"columns":columns,"engine":owner}));
                if let Some(source) = definition.get("source_metadata") {
                    let mut source = source.clone();
                    source["table"] = json!(table);
                    if let Some(indexes) = source["indexes"].as_array() {
                        for index in indexes {
                            column_types(definition, &index["column"])?;
                        }
                    }
                    for dependency in crate::model::dependencies(definition) {
                        let connector = object(objects, &dependency, "connector")?;
                        engines.insert(dependency, json!({"dialect":connector["adapter"]}));
                    }
                    metadata.push(source);
                }
            }
            "entity" => {
                let dataset = object(objects, text(definition, "dataset")?, "dataset")?;
                let mapping = &definition["mapping"];
                if mapping["table"] != dataset["table"] {
                    return Err(invalid(format!("{id}: entity table differs from dataset")));
                }
                if !labels.insert(text(mapping, "label")?) {
                    return Err(invalid("duplicate entity label"));
                }
                column_types(dataset, &mapping["id"])?;
                properties(dataset, mapping)?;
                nodes.push(mapping.clone());
            }
            "relationship" | "computed_relationship" => {
                let source = object(objects, text(definition, "source")?, "entity")?;
                let target = object(objects, text(definition, "target")?, "entity")?;
                let mapping = &definition["mapping"];
                if definition["kind"] == "relationship" {
                    if !edge_labels.insert(text(mapping, "label")?) {
                        return Err(invalid("duplicate relationship label"));
                    }
                    let dataset = object(objects, text(definition, "dataset")?, "dataset")?;
                    if mapping["table"] != dataset["table"]
                        || mapping["source_label"] != source["mapping"]["label"]
                        || mapping["target_label"] != target["mapping"]["label"]
                    {
                        return Err(invalid(format!(
                            "{id}: relationship endpoints/table differ from dependencies"
                        )));
                    }
                    column_types(dataset, &mapping["id"])?;
                    properties(dataset, mapping)?;
                    for (entity, key) in [(source, "source"), (target, "target")] {
                        let endpoint = object(objects, text(entity, "dataset")?, "dataset")?;
                        if column_types(dataset, &mapping[key])?
                            != column_types(endpoint, &entity["mapping"]["id"])?
                        {
                            return Err(invalid(format!("{id}: endpoint key arity/types differ")));
                        }
                    }
                    edges.push(mapping.clone());
                } else {
                    if !edge_labels.insert(text(mapping, "name")?) {
                        return Err(invalid("duplicate relationship label"));
                    }
                    if mapping["source"] != source["mapping"]["label"]
                        || mapping["target"] != target["mapping"]["label"]
                    {
                        return Err(invalid("computed endpoints differ from dependencies"));
                    }
                    if mapping.get("limit_per_source").is_some()
                        && mapping["order_by"].as_array().is_none_or(Vec::is_empty)
                    {
                        return Err(invalid("ranked relationships require order_by"));
                    }
                    computed.push(mapping.clone());
                }
            }
            "retrieval" => {
                object(objects, text(definition, "target")?, "entity")?;
                object(objects, text(definition, "connector")?, "connector")?;
            }
            "connector" => (),
            _ => return Err(invalid("unknown object kind")),
        }
    }
    Ok(
        json!({"tables":tables,"nodes":nodes,"edges":edges,"computed_relationships":computed,
        "source_metadata":metadata,"engines":engines,"execution_engine":graph.execution_connector}),
    )
}
