use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginStage {
    Observer,
    TraceSource,
    Enricher,
    Verify,
    Render,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub protocol_version: String,
    pub stage: PluginStage,
    pub entrypoint: Vec<String>,
    pub language: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub options_schema: Option<Value>,
    #[serde(default)]
    pub output_schema: Option<Value>,
    #[serde(skip)]
    pub manifest_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    pub protocol_version: String,
    pub stage: PluginStage,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginBatchRequest {
    pub protocol_version: String,
    pub stage: PluginStage,
    pub payloads: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginErrorPayload {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResponse {
    pub ok: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<PluginErrorPayload>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginBatchResponse {
    pub ok: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<PluginErrorPayload>,
    #[serde(default)]
    pub responses: Vec<PluginResponse>,
}

pub fn build_canonical_payload(stage: &PluginStage, input: Value, options: Option<Value>) -> Value {
    let mut payload = Map::new();
    payload.insert("input".to_string(), input.clone());

    match stage {
        PluginStage::Observer => {
            payload.insert("raw_input".to_string(), input);
        }
        PluginStage::TraceSource => {
            payload.insert("source".to_string(), input);
        }
        PluginStage::Enricher => {
            payload.insert("records".to_string(), input);
        }
        PluginStage::Verify => {
            payload.insert("pearl_ir".to_string(), input);
        }
        PluginStage::Render => {}
    }

    if let Some(options) = options {
        payload.insert("options".to_string(), options);
    }

    Value::Object(payload)
}

impl PluginManifest {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let mut manifest: Self = serde_json::from_str(&content)?;
        manifest.manifest_dir = path.parent().map(Path::to_path_buf);
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(LogicPearlError::message(
                "plugin manifest name must be non-empty",
            ));
        }
        if self.protocol_version != "1" {
            return Err(LogicPearlError::message(format!(
                "unsupported plugin protocol_version: {}",
                self.protocol_version
            )));
        }
        if self.entrypoint.is_empty() {
            return Err(LogicPearlError::message(
                "plugin manifest entrypoint must contain at least one command segment",
            ));
        }
        validate_declared_schema("input_schema", self.input_schema.as_ref())?;
        validate_declared_schema("options_schema", self.options_schema.as_ref())?;
        validate_declared_schema("output_schema", self.output_schema.as_ref())?;
        Ok(())
    }

    pub fn supports_capability(&self, capability: &str) -> bool {
        self.capabilities
            .as_ref()
            .map(|caps| caps.iter().any(|item| item == capability))
            .unwrap_or(false)
    }
}

pub fn run_plugin(manifest: &PluginManifest, request: &PluginRequest) -> Result<PluginResponse> {
    if manifest.stage != request.stage {
        return Err(LogicPearlError::message(format!(
            "plugin stage mismatch: manifest is {:?}, request is {:?}",
            manifest.stage, request.stage
        )));
    }
    validate_plugin_request_contract(manifest, request)?;

    let stdout = run_plugin_raw(manifest, request)?;
    parse_plugin_response(manifest, &stdout)
}

pub fn run_plugin_batch(
    manifest: &PluginManifest,
    stage: PluginStage,
    payloads: &[Value],
) -> Result<Vec<PluginResponse>> {
    if manifest.stage != stage {
        return Err(LogicPearlError::message(format!(
            "plugin stage mismatch: manifest is {:?}, request is {:?}",
            manifest.stage, stage
        )));
    }
    if payloads.is_empty() {
        return Ok(Vec::new());
    }
    if !manifest.supports_capability("batch_requests") {
        return payloads
            .iter()
            .map(|payload| {
                validate_plugin_payload_contract(manifest, &stage, payload)?;
                run_plugin(
                    manifest,
                    &PluginRequest {
                        protocol_version: "1".to_string(),
                        stage: stage.clone(),
                        payload: payload.clone(),
                    },
                )
            })
            .collect();
    }
    for payload in payloads {
        validate_plugin_payload_contract(manifest, &stage, payload)?;
    }

    let stdout = run_plugin_raw(
        manifest,
        &PluginBatchRequest {
            protocol_version: "1".to_string(),
            stage: stage.clone(),
            payloads: payloads.to_vec(),
        },
    )?;
    let batch: PluginBatchResponse = serde_json::from_str(&stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid batch JSON: {}",
            manifest.name, err
        ))
    })?;
    if !batch.ok {
        if let Some(error) = &batch.error {
            return Err(LogicPearlError::message(format!(
                "plugin {} failed [{}]: {}",
                manifest.name, error.code, error.message
            )));
        }
        return Err(LogicPearlError::message(format!(
            "plugin {} returned ok=false without structured batch error",
            manifest.name
        )));
    }
    if batch.responses.len() != payloads.len() {
        return Err(LogicPearlError::message(format!(
            "plugin {} returned {} batch responses for {} payloads",
            manifest.name,
            batch.responses.len(),
            payloads.len()
        )));
    }
    for response in &batch.responses {
        validate_ok_plugin_response(manifest, response)?;
    }
    Ok(batch.responses)
}

pub fn manifest_contract_summary(manifest: &PluginManifest) -> Value {
    serde_json::json!({
        "input_schema": manifest.input_schema,
        "options_schema": manifest.options_schema,
        "output_schema": manifest.output_schema,
    })
}

fn run_plugin_raw<T: Serialize>(manifest: &PluginManifest, request: &T) -> Result<String> {
    let program = manifest
        .entrypoint
        .first()
        .ok_or_else(|| LogicPearlError::message("plugin entrypoint is empty"))?;
    let resolved_program = resolve_entrypoint_segment(manifest, program, true);
    let mut command = Command::new(&resolved_program);
    if manifest.entrypoint.len() > 1 {
        let args: Vec<String> = manifest.entrypoint[1..]
            .iter()
            .map(|segment| resolve_entrypoint_segment(manifest, segment, false))
            .collect();
        command.args(&args);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn()?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| LogicPearlError::message("failed to open plugin stdin"))?;
    let payload = serde_json::to_vec(request)?;
    stdin.write_all(&payload)?;
    stdin.write_all(b"\n")?;
    drop(child.stdin.take());

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(LogicPearlError::message(format!(
            "plugin {} exited with status {}{}",
            manifest.name,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        )));
    }

    String::from_utf8(output.stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid UTF-8: {}",
            manifest.name, err
        ))
    })
}

fn parse_plugin_response(manifest: &PluginManifest, stdout: &str) -> Result<PluginResponse> {
    let response: PluginResponse = serde_json::from_str(stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid JSON: {}",
            manifest.name, err
        ))
    })?;
    validate_ok_plugin_response(manifest, &response)?;
    Ok(response)
}

fn validate_ok_plugin_response(manifest: &PluginManifest, response: &PluginResponse) -> Result<()> {
    if !response.ok {
        if let Some(error) = &response.error {
            return Err(LogicPearlError::message(format!(
                "plugin {} failed [{}]: {}",
                manifest.name, error.code, error.message
            )));
        }
        return Err(LogicPearlError::message(format!(
            "plugin {} returned ok=false without structured error",
            manifest.name
        )));
    }
    if let Some(schema) = &manifest.output_schema {
        let response_value = serde_json::to_value(response).map_err(LogicPearlError::from)?;
        validate_value_against_declared_schema(
            "output_schema",
            schema,
            &response_value,
            "$response",
        )?;
    }
    Ok(())
}

fn validate_plugin_request_contract(
    manifest: &PluginManifest,
    request: &PluginRequest,
) -> Result<()> {
    validate_plugin_payload_contract(manifest, &request.stage, &request.payload)
}

fn validate_plugin_payload_contract(
    manifest: &PluginManifest,
    stage: &PluginStage,
    payload: &Value,
) -> Result<()> {
    if let Some(schema) = &manifest.input_schema {
        let input = extract_payload_input(stage, payload).ok_or_else(|| {
            LogicPearlError::message(format!(
                "plugin {} manifest declares input_schema but request payload is missing payload.input",
                manifest.name
            ))
        })?;
        validate_value_against_declared_schema("input_schema", schema, input, "$payload.input")?;
    }
    if let Some(schema) = &manifest.options_schema {
        let null = Value::Null;
        let options = extract_payload_options(payload).unwrap_or(&null);
        validate_value_against_declared_schema(
            "options_schema",
            schema,
            options,
            "$payload.options",
        )?;
    }
    Ok(())
}

fn extract_payload_input<'a>(stage: &PluginStage, payload: &'a Value) -> Option<&'a Value> {
    let object = payload.as_object()?;
    object
        .get("input")
        .or_else(|| compatibility_alias(stage).and_then(|alias| object.get(alias)))
}

fn extract_payload_options(payload: &Value) -> Option<&Value> {
    payload.as_object().and_then(|object| object.get("options"))
}

fn compatibility_alias(stage: &PluginStage) -> Option<&'static str> {
    match stage {
        PluginStage::Observer => Some("raw_input"),
        PluginStage::TraceSource => Some("source"),
        PluginStage::Enricher => Some("records"),
        PluginStage::Verify => Some("pearl_ir"),
        PluginStage::Render => None,
    }
}

fn validate_declared_schema(label: &str, schema: Option<&Value>) -> Result<()> {
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

fn validate_value_against_declared_schema(
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

fn resolve_entrypoint_segment(
    manifest: &PluginManifest,
    segment: &str,
    executable: bool,
) -> String {
    if let Some(dir) = &manifest.manifest_dir {
        let candidate = dir.join(segment);
        if candidate.exists() {
            return candidate.display().to_string();
        }
        if executable && !segment.contains(std::path::MAIN_SEPARATOR) {
            return segment.to_string();
        }
    }
    segment.to_string()
}

#[cfg(test)]
mod tests {
    use super::{PluginManifest, PluginStage};
    use serde_json::json;

    #[test]
    fn validates_basic_manifest() {
        let manifest = PluginManifest {
            name: "demo".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
            language: Some("python".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: None,
        };
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn validates_declared_input_options_and_output_schemas() {
        let manifest = PluginManifest {
            name: "demo".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
            language: Some("python".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: Some(json!({
                "type": "object",
                "required": ["age", "member"],
                "properties": {
                    "age": { "type": "integer" },
                    "member": { "type": "boolean" }
                },
                "additionalProperties": false
            })),
            options_schema: Some(json!({
                "type": ["object", "null"],
                "properties": {
                    "mode": { "type": "string" }
                },
                "additionalProperties": false
            })),
            output_schema: Some(json!({
                "type": "object",
                "required": ["ok", "features"],
                "properties": {
                    "ok": { "const": true },
                    "features": {
                        "type": "object",
                        "required": ["age"],
                        "properties": {
                            "age": { "type": "integer" }
                        }
                    }
                }
            })),
            manifest_dir: None,
        };
        assert!(manifest.validate().is_ok());

        let request = super::PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            payload: super::build_canonical_payload(
                &PluginStage::Observer,
                json!({"age": 34, "member": true}),
                Some(json!({"mode": "strict"})),
            ),
        };
        assert!(super::validate_plugin_request_contract(&manifest, &request).is_ok());

        let bad_request = super::PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            payload: super::build_canonical_payload(
                &PluginStage::Observer,
                json!({"age": "34", "member": true, "extra": 1}),
                None,
            ),
        };
        assert!(super::validate_plugin_request_contract(&manifest, &bad_request).is_err());

        let good_response = super::PluginResponse {
            ok: true,
            warnings: Vec::new(),
            error: None,
            extra: serde_json::Map::from_iter([("features".to_string(), json!({"age": 34}))]),
        };
        assert!(super::validate_ok_plugin_response(&manifest, &good_response).is_ok());

        let bad_response = super::PluginResponse {
            ok: true,
            warnings: Vec::new(),
            error: None,
            extra: serde_json::Map::new(),
        };
        assert!(super::validate_ok_plugin_response(&manifest, &bad_response).is_err());
    }
}
