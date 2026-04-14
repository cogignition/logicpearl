// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use serde_json::{Map, Value};

const SUPPORTED_SCHEMA_VALIDATION_KEYWORDS: &[&str] = &[
    "additionalProperties",
    "const",
    "enum",
    "items",
    "properties",
    "required",
    "type",
];
const SUPPORTED_SCHEMA_ANNOTATION_KEYWORDS: &[&str] = &["$id", "$schema", "description", "title"];

pub(crate) fn validate_declared_schema(label: &str, schema: Option<&Value>) -> Result<()> {
    if let Some(schema) = schema {
        validate_schema_document(label, schema, format!("${label}"))?;
    }
    Ok(())
}

fn validate_schema_document(label: &str, schema: &Value, path: String) -> Result<()> {
    let Some(object) = schema.as_object() else {
        return Err(LogicPearlError::message(format!(
            "{label} must be a JSON object at {path}"
        )));
    };
    validate_schema_keywords(label, object, &path)?;
    validate_schema_annotations(label, object, &path)?;
    if let Some(value) = object.get("type") {
        validate_schema_type_decl(label, value, &path)?;
    }
    if let Some(value) = object.get("properties") {
        let properties = value.as_object().ok_or_else(|| {
            LogicPearlError::message(format!(
                "{label} properties must be an object at {path}.properties"
            ))
        })?;
        for (key, child) in properties {
            validate_schema_document(label, child, format!("{path}.properties.{key}"))?;
        }
    }
    if let Some(value) = object.get("required") {
        let required = value.as_array().ok_or_else(|| {
            LogicPearlError::message(format!(
                "{label} required must be an array at {path}.required"
            ))
        })?;
        for item in required {
            if item
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .is_none()
            {
                return Err(LogicPearlError::message(format!(
                    "{label} required entries must be non-empty strings at {path}.required"
                )));
            }
        }
    }
    if let Some(value) = object.get("items") {
        validate_schema_document(label, value, format!("{path}.items"))?;
    }
    if let Some(value) = object.get("additionalProperties") {
        match value {
            Value::Bool(_) => {}
            Value::Object(_) => {
                validate_schema_document(label, value, format!("{path}.additionalProperties"))?
            }
            _ => {
                return Err(LogicPearlError::message(format!(
                    "{label} additionalProperties must be a boolean or object at {path}.additionalProperties"
                )));
            }
        }
    }
    if let Some(value) = object.get("enum") {
        if value.as_array().filter(|items| !items.is_empty()).is_none() {
            return Err(LogicPearlError::message(format!(
                "{label} enum must be a non-empty array at {path}.enum"
            )));
        }
    }
    Ok(())
}

fn validate_schema_keywords(label: &str, object: &Map<String, Value>, path: &str) -> Result<()> {
    for key in object.keys() {
        if is_supported_schema_keyword(key) {
            continue;
        }
        return Err(LogicPearlError::message(format!(
            "{label} uses unsupported LogicPearl schema subset keyword {key:?} at {path}; supported validation keywords are: {}; supported annotation keywords are: {}. Use a plugin smoke test or an external JSON Schema validator for full JSON Schema constraints.",
            SUPPORTED_SCHEMA_VALIDATION_KEYWORDS.join(", "),
            SUPPORTED_SCHEMA_ANNOTATION_KEYWORDS.join(", ")
        )));
    }
    Ok(())
}

fn is_supported_schema_keyword(key: &str) -> bool {
    SUPPORTED_SCHEMA_VALIDATION_KEYWORDS.contains(&key)
        || SUPPORTED_SCHEMA_ANNOTATION_KEYWORDS.contains(&key)
}

fn validate_schema_annotations(label: &str, object: &Map<String, Value>, path: &str) -> Result<()> {
    for key in SUPPORTED_SCHEMA_ANNOTATION_KEYWORDS {
        if let Some(value) = object.get(*key) {
            if !value.is_string() {
                return Err(LogicPearlError::message(format!(
                    "{label} annotation keyword {key:?} must be a string at {path}.{key}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_schema_type_decl(label: &str, value: &Value, path: &str) -> Result<()> {
    match value {
        Value::String(kind) => validate_schema_type_name(label, kind, path),
        Value::Array(items) if !items.is_empty() => {
            for item in items {
                let kind = item.as_str().ok_or_else(|| {
                    LogicPearlError::message(format!(
                        "{label} type arrays must contain only strings at {path}"
                    ))
                })?;
                validate_schema_type_name(label, kind, path)?;
            }
            Ok(())
        }
        _ => Err(LogicPearlError::message(format!(
            "{label} type must be a string or non-empty array of strings at {path}"
        ))),
    }
}

fn validate_schema_type_name(label: &str, kind: &str, path: &str) -> Result<()> {
    match kind {
        "null" | "boolean" | "integer" | "number" | "string" | "array" | "object" => Ok(()),
        _ => Err(LogicPearlError::message(format!(
            "{label} uses unsupported JSON Schema type {kind:?} at {path}"
        ))),
    }
}

pub(crate) fn validate_value_against_declared_schema(
    label: &str,
    schema: &Value,
    value: &Value,
    path: &str,
) -> Result<()> {
    let object = schema
        .as_object()
        .ok_or_else(|| LogicPearlError::message(format!("{label} must be a JSON object")))?;

    if let Some(type_decl) = object.get("type") {
        let matches = schema_type_names(type_decl)?
            .iter()
            .any(|kind| value_matches_type(value, kind));
        if !matches {
            return Err(LogicPearlError::message(format!(
                "{label} rejected {path}: expected type {}, got {}",
                render_schema_types(type_decl)?,
                describe_json_type(value)
            )));
        }
    }

    if let Some(expected) = object.get("const") {
        if value != expected {
            return Err(LogicPearlError::message(format!(
                "{label} rejected {path}: value did not match const"
            )));
        }
    }

    if let Some(choices) = object.get("enum").and_then(Value::as_array) {
        if !choices.iter().any(|choice| choice == value) {
            return Err(LogicPearlError::message(format!(
                "{label} rejected {path}: value was not in enum"
            )));
        }
    }

    if let Some(required) = object.get("required").and_then(Value::as_array) {
        if let Some(map) = value.as_object() {
            for field in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(field) {
                    return Err(LogicPearlError::message(format!(
                        "{label} rejected {path}: missing required field {field:?}"
                    )));
                }
            }
        }
    }

    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        if let Some(map) = value.as_object() {
            for (key, child_schema) in properties {
                if let Some(child_value) = map.get(key) {
                    validate_value_against_declared_schema(
                        label,
                        child_schema,
                        child_value,
                        &format!("{path}.{key}"),
                    )?;
                }
            }

            match object.get("additionalProperties") {
                Some(Value::Bool(false)) => {
                    for key in map.keys() {
                        if !properties.contains_key(key) {
                            return Err(LogicPearlError::message(format!(
                                "{label} rejected {path}: unexpected field {key:?}"
                            )));
                        }
                    }
                }
                Some(Value::Object(_)) => {
                    let extra_schema = object
                        .get("additionalProperties")
                        .expect("checked additionalProperties");
                    for (key, child_value) in map {
                        if !properties.contains_key(key) {
                            validate_value_against_declared_schema(
                                label,
                                extra_schema,
                                child_value,
                                &format!("{path}.{key}"),
                            )?;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(items_schema) = object.get("items") {
        if let Some(items) = value.as_array() {
            for (index, item) in items.iter().enumerate() {
                validate_value_against_declared_schema(
                    label,
                    items_schema,
                    item,
                    &format!("{path}[{index}]"),
                )?;
            }
        }
    }

    Ok(())
}

fn schema_type_names(value: &Value) -> Result<Vec<&str>> {
    match value {
        Value::String(kind) => Ok(vec![kind.as_str()]),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str().ok_or_else(|| {
                    LogicPearlError::message("schema type arrays must contain only strings")
                })
            })
            .collect(),
        _ => Err(LogicPearlError::message(
            "schema type must be a string or non-empty array of strings",
        )),
    }
}

fn render_schema_types(value: &Value) -> Result<String> {
    Ok(schema_type_names(value)?.join(" | "))
}

fn value_matches_type(value: &Value, kind: &str) -> bool {
    match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => false,
    }
}

fn describe_json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) => {
            if number.as_i64().is_some() || number.as_u64().is_some() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
