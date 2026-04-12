// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PLUGIN_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PLUGIN_STDERR_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_PLUGIN_TIMEOUT_MS: u64 = 30_000;
const PLUGIN_SPAWN_TEXT_BUSY_RETRIES: usize = 5;
const PLUGIN_SPAWN_TEXT_BUSY_BACKOFF_MS: u64 = 20;
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

#[cfg(unix)]
use libc::{getpgid, getpgrp, kill, SIGKILL, SIGTERM};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginExecutionPolicy {
    pub default_timeout_ms: u64,
    pub allow_no_timeout: bool,
    pub allow_absolute_entrypoint: bool,
    pub allow_path_lookup: bool,
}

impl Default for PluginExecutionPolicy {
    fn default() -> Self {
        Self {
            default_timeout_ms: DEFAULT_PLUGIN_TIMEOUT_MS,
            allow_no_timeout: false,
            allow_absolute_entrypoint: false,
            allow_path_lookup: false,
        }
    }
}

impl PluginExecutionPolicy {
    #[must_use]
    pub fn trusted_local() -> Self {
        Self {
            allow_no_timeout: true,
            allow_absolute_entrypoint: true,
            allow_path_lookup: true,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_default_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.default_timeout_ms = timeout_ms;
        self
    }

    #[must_use]
    pub fn with_allow_no_timeout(mut self, allow: bool) -> Self {
        self.allow_no_timeout = allow;
        self
    }

    #[must_use]
    pub fn with_allow_absolute_entrypoint(mut self, allow: bool) -> Self {
        self.allow_absolute_entrypoint = allow;
        self
    }

    #[must_use]
    pub fn with_allow_path_lookup(mut self, allow: bool) -> Self {
        self.allow_path_lookup = allow;
        self
    }
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

pub fn build_canonical_payload(
    _stage: &PluginStage,
    input: Value,
    options: Option<Value>,
) -> Value {
    let mut payload = Map::new();
    payload.insert("input".to_string(), input);

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
    run_plugin_with_policy(manifest, request, &PluginExecutionPolicy::default())
}

pub fn run_plugin_with_policy(
    manifest: &PluginManifest,
    request: &PluginRequest,
    policy: &PluginExecutionPolicy,
) -> Result<PluginResponse> {
    if manifest.stage != request.stage {
        return Err(LogicPearlError::message(format!(
            "plugin stage mismatch: manifest is {:?}, request is {:?}",
            manifest.stage, request.stage
        )));
    }
    validate_plugin_request_contract(manifest, request)?;

    let stdout = run_plugin_raw(manifest, request, policy)?;
    parse_plugin_response(manifest, &stdout)
}

pub fn run_plugin_batch(
    manifest: &PluginManifest,
    stage: PluginStage,
    payloads: &[Value],
) -> Result<Vec<PluginResponse>> {
    run_plugin_batch_with_policy(manifest, stage, payloads, &PluginExecutionPolicy::default())
}

pub fn run_plugin_batch_with_policy(
    manifest: &PluginManifest,
    stage: PluginStage,
    payloads: &[Value],
    policy: &PluginExecutionPolicy,
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
                run_plugin_with_policy(
                    manifest,
                    &PluginRequest {
                        protocol_version: "1".to_string(),
                        stage: stage.clone(),
                        payload: payload.clone(),
                    },
                    policy,
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
        policy,
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

fn run_plugin_raw<T: Serialize>(
    manifest: &PluginManifest,
    request: &T,
    policy: &PluginExecutionPolicy,
) -> Result<String> {
    let entrypoint = resolve_entrypoint(manifest, policy)?;
    let mut command = Command::new(&entrypoint.program);
    command.args(&entrypoint.args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let timeout_ms = effective_timeout_ms(manifest, policy)?;
    let mut child = spawn_plugin_process(&mut command)?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| LogicPearlError::message("failed to open plugin stdin"))?;
    let payload = serde_json::to_vec(request)?;
    stdin.write_all(&payload)?;
    stdin.write_all(b"\n")?;
    drop(child.stdin.take());

    let stdout_handle = spawn_pipe_reader(
        child
            .stdout
            .take()
            .ok_or_else(|| LogicPearlError::message("failed to open plugin stdout"))?,
        MAX_PLUGIN_STDOUT_BYTES,
    );
    let stderr_handle = spawn_pipe_reader(
        child
            .stderr
            .take()
            .ok_or_else(|| LogicPearlError::message("failed to open plugin stderr"))?,
        MAX_PLUGIN_STDERR_BYTES,
    );

    let (status, timed_out) = wait_for_plugin_exit(timeout_ms, &mut child)?;
    let stdout = join_pipe_reader(manifest, "stdout", stdout_handle)?;
    let stderr = String::from_utf8_lossy(&join_pipe_reader(manifest, "stderr", stderr_handle)?)
        .trim()
        .to_string();

    if timed_out {
        let timeout_display = timeout_ms.unwrap_or_default();
        return Err(LogicPearlError::message(format!(
            "plugin {} exceeded timeout_ms={} and was terminated{}",
            manifest.name,
            timeout_display,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        )));
    }

    if !status.success() {
        return Err(LogicPearlError::message(format!(
            "plugin {} exited with status {}{}",
            manifest.name,
            status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        )));
    }

    String::from_utf8(stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid UTF-8: {}",
            manifest.name, err
        ))
    })
}

pub fn manifest_contract_summary(manifest: &PluginManifest) -> Value {
    serde_json::json!({
        "input_schema": manifest.input_schema,
        "options_schema": manifest.options_schema,
        "output_schema": manifest.output_schema,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPluginEntrypoint {
    program: String,
    args: Vec<String>,
}

fn resolve_entrypoint(
    manifest: &PluginManifest,
    policy: &PluginExecutionPolicy,
) -> Result<ResolvedPluginEntrypoint> {
    let program = manifest
        .entrypoint
        .first()
        .ok_or_else(|| LogicPearlError::message("plugin entrypoint is empty"))?;
    if program.trim().is_empty() {
        return Err(LogicPearlError::message(
            "plugin entrypoint program must be non-empty",
        ));
    }

    let resolved_program = resolve_entrypoint_program(manifest, policy, program)?;
    let args = manifest
        .entrypoint
        .iter()
        .skip(1)
        .map(|segment| resolve_entrypoint_arg(manifest, policy, segment))
        .collect::<Result<Vec<_>>>()?;

    Ok(ResolvedPluginEntrypoint {
        program: resolved_program,
        args,
    })
}

fn resolve_entrypoint_program(
    manifest: &PluginManifest,
    policy: &PluginExecutionPolicy,
    program: &str,
) -> Result<String> {
    let program_path = Path::new(program);
    if program_path.is_absolute() {
        if !policy.allow_absolute_entrypoint {
            return Err(LogicPearlError::message(format!(
                "plugin {} entrypoint uses absolute program path {}; rerun with an execution policy that allows absolute entrypoints only for trusted manifests",
                manifest.name, program
            )));
        }
        return Ok(program.to_string());
    }

    if let Some(manifest_relative) = manifest_relative_existing_path(manifest, program) {
        return Ok(manifest_relative);
    }

    if has_path_separator(program) {
        return Err(LogicPearlError::message(format!(
            "plugin {} entrypoint path was not found relative to the manifest: {}",
            manifest.name, program
        )));
    }

    if policy.allow_path_lookup {
        return Ok(program.to_string());
    }

    if is_allowed_manifest_script_interpreter(program) && has_manifest_local_script_arg(manifest) {
        return Ok(program.to_string());
    }

    Err(LogicPearlError::message(format!(
        "plugin {} entrypoint program {program:?} is not manifest-relative and PATH lookup is disabled; use a manifest-relative script path or enable PATH lookup only for trusted manifests",
        manifest.name
    )))
}

fn resolve_entrypoint_arg(
    manifest: &PluginManifest,
    policy: &PluginExecutionPolicy,
    segment: &str,
) -> Result<String> {
    if segment.trim().is_empty() {
        return Err(LogicPearlError::message(format!(
            "plugin {} entrypoint arguments must be non-empty",
            manifest.name
        )));
    }

    let path = Path::new(segment);
    if path.is_absolute() && !policy.allow_absolute_entrypoint {
        return Err(LogicPearlError::message(format!(
            "plugin {} entrypoint argument uses absolute path {}; enable absolute entrypoints only for trusted manifests",
            manifest.name, segment
        )));
    }
    if path.is_absolute() {
        return Ok(segment.to_string());
    }

    if let Some(manifest_relative) = manifest_relative_existing_path(manifest, segment) {
        return Ok(manifest_relative);
    }

    if has_path_separator(segment) {
        return Err(LogicPearlError::message(format!(
            "plugin {} entrypoint argument path was not found relative to the manifest: {}",
            manifest.name, segment
        )));
    }

    Ok(segment.to_string())
}

fn manifest_relative_existing_path(manifest: &PluginManifest, segment: &str) -> Option<String> {
    manifest.manifest_dir.as_ref().and_then(|dir| {
        let candidate = dir.join(segment);
        candidate.exists().then(|| candidate.display().to_string())
    })
}

fn has_path_separator(segment: &str) -> bool {
    segment.contains('/') || segment.contains('\\')
}

fn has_manifest_local_script_arg(manifest: &PluginManifest) -> bool {
    manifest
        .entrypoint
        .iter()
        .skip(1)
        .any(|segment| manifest_relative_existing_path(manifest, segment).is_some())
}

fn is_allowed_manifest_script_interpreter(program: &str) -> bool {
    let normalized = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "bash" | "bun" | "deno" | "node" | "perl" | "php" | "python" | "python3" | "ruby" | "sh"
    )
}

fn effective_timeout_ms(
    manifest: &PluginManifest,
    policy: &PluginExecutionPolicy,
) -> Result<Option<u64>> {
    match manifest.timeout_ms {
        Some(0) if policy.allow_no_timeout => Ok(None),
        Some(0) => Err(LogicPearlError::message(format!(
            "plugin {} declares timeout_ms=0, which disables the plugin timeout; enable no-timeout execution only for trusted manifests",
            manifest.name
        ))),
        Some(timeout_ms) => Ok(Some(timeout_ms)),
        None if policy.default_timeout_ms == 0 && policy.allow_no_timeout => Ok(None),
        None if policy.default_timeout_ms == 0 => Err(LogicPearlError::message(format!(
            "plugin {} has no timeout and the execution policy default is disabled; enable no-timeout execution only for trusted manifests",
            manifest.name
        ))),
        None => Ok(Some(policy.default_timeout_ms)),
    }
}

fn spawn_plugin_process(command: &mut Command) -> std::io::Result<Child> {
    for attempt in 0..=PLUGIN_SPAWN_TEXT_BUSY_RETRIES {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error)
                if is_executable_file_busy(&error) && attempt < PLUGIN_SPAWN_TEXT_BUSY_RETRIES =>
            {
                let backoff =
                    PLUGIN_SPAWN_TEXT_BUSY_BACKOFF_MS * u64::try_from(attempt + 1).unwrap_or(1);
                thread::sleep(Duration::from_millis(backoff));
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("spawn loop returns after the final attempt")
}

#[cfg(unix)]
fn is_executable_file_busy(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(not(unix))]
fn is_executable_file_busy(_error: &std::io::Error) -> bool {
    false
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    reader: R,
    max_bytes: usize,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    spawn_limited_pipe_reader(reader, max_bytes)
}

fn spawn_limited_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || read_limited(&mut reader, max_bytes))
}

fn read_limited(reader: &mut impl Read, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut exceeded_limit = false;
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            if exceeded_limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("plugin output exceeded {max_bytes} bytes"),
                ));
            }
            return Ok(buffer);
        }
        if exceeded_limit {
            continue;
        }
        let remaining = max_bytes.saturating_sub(buffer.len());
        if read > remaining {
            buffer.extend_from_slice(&chunk[..remaining]);
            exceeded_limit = true;
        } else {
            buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

fn join_pipe_reader(
    manifest: &PluginManifest,
    stream: &str,
    handle: thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let result = handle.join().map_err(|_| {
        LogicPearlError::message(format!(
            "plugin {} {} reader thread panicked",
            manifest.name, stream
        ))
    })?;
    result.map_err(|err| {
        LogicPearlError::message(format!(
            "failed to read plugin {} {}: {}",
            manifest.name, stream, err
        ))
    })
}

fn wait_for_plugin_exit(timeout_ms: Option<u64>, child: &mut Child) -> Result<(ExitStatus, bool)> {
    if let Some(timeout_ms) = timeout_ms {
        let timeout = Duration::from_millis(timeout_ms);
        let started_at = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, false));
            }
            if started_at.elapsed() >= timeout {
                terminate_plugin_process(child);
                let status = child.wait()?;
                return Ok((status, true));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    Ok((child.wait()?, false))
}

#[cfg(unix)]
fn terminate_plugin_process(child: &mut Child) {
    let child_process_group = safe_child_process_group(child);
    if let Some(process_group) = child_process_group {
        signal_process_group(process_group, SIGTERM);
    } else {
        let _ = child.kill();
    }
    thread::sleep(Duration::from_millis(50));
    if child.try_wait().ok().flatten().is_none() {
        if let Some(process_group) = child_process_group {
            signal_process_group(process_group, SIGKILL);
        }
        let _ = child.kill();
    }
}

#[cfg(unix)]
fn safe_child_process_group(child: &Child) -> Option<i32> {
    let pid = i32::try_from(child.id()).ok()?;
    // SAFETY: getpgid only reads kernel process metadata for the spawned child pid.
    let process_group = unsafe { getpgid(pid) };
    if process_group <= 0 {
        return None;
    }
    // SAFETY: getpgrp has no arguments and returns the current process group id.
    let parent_process_group = unsafe { getpgrp() };
    if process_group == parent_process_group {
        return None;
    }
    Some(process_group)
}

#[cfg(unix)]
fn signal_process_group(process_group: i32, signal: i32) {
    // SAFETY: negative pid values are the POSIX API for signaling a process group.
    let _ = unsafe { kill(-process_group, signal) };
}

#[cfg(not(unix))]
fn terminate_plugin_process(child: &mut Child) {
    let _ = child.kill();
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

fn extract_payload_input<'a>(_stage: &PluginStage, payload: &'a Value) -> Option<&'a Value> {
    payload.as_object().and_then(|object| object.get("input"))
}

fn extract_payload_options(payload: &Value) -> Option<&Value> {
    payload.as_object().and_then(|object| object.get("options"))
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

#[cfg(test)]
mod tests {
    use super::{
        run_plugin, run_plugin_with_policy, PluginExecutionPolicy, PluginManifest, PluginRequest,
        PluginStage,
    };
    use serde_json::json;
    use tempfile::tempdir;

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

    #[test]
    fn rejects_unsupported_schema_subset_keywords() {
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
                "properties": {
                    "age": {
                        "type": "integer",
                        "minimum": 0
                    }
                }
            })),
            options_schema: None,
            output_schema: None,
            manifest_dir: None,
        };

        let err = manifest.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported LogicPearl schema subset keyword \"minimum\""));
    }

    #[test]
    fn accepts_schema_subset_annotation_keywords() {
        let manifest = PluginManifest {
            name: "demo".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["python3".to_string(), "plugin.py".to_string()],
            language: Some("python".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: Some(json!({
                "$schema": "https://logicpearl.com/schema/plugin-contract-subset",
                "title": "Observer input",
                "description": "Annotation fields are accepted but do not add validation.",
                "type": "object"
            })),
            options_schema: None,
            output_schema: None,
            manifest_dir: None,
        };

        assert!(manifest.validate().is_ok());
    }

    #[cfg(unix)]
    fn write_plugin_script(script_body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("plugin.sh");
        std::fs::write(&path, script_body).expect("write script");
        let mut permissions = std::fs::metadata(&path).expect("stat script").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod script");
        (dir, path)
    }

    #[cfg(unix)]
    fn test_request() -> PluginRequest {
        PluginRequest {
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            payload: super::build_canonical_payload(
                &PluginStage::Observer,
                json!({"value": 1}),
                None,
            ),
        }
    }

    #[cfg(unix)]
    #[test]
    fn enforces_plugin_timeout_when_declared() {
        let (dir, _script_path) =
            write_plugin_script("#!/bin/sh\nsleep 1\nprintf '{\"ok\":true}\\n'\n");
        let manifest = PluginManifest {
            name: "slow".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["plugin.sh".to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: Some(50),
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let error = run_plugin(&manifest, &test_request()).expect_err("plugin should time out");
        let message = error.to_string();
        assert!(message.contains("exceeded timeout_ms=50"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn applies_policy_default_timeout_when_manifest_timeout_is_unset() {
        let (dir, _script_path) =
            write_plugin_script("#!/bin/sh\nsleep 1\nprintf '{\"ok\":true}\\n'\n");
        let manifest = PluginManifest {
            name: "slow-default".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["plugin.sh".to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let policy = PluginExecutionPolicy::default().with_default_timeout_ms(50);
        let error = run_plugin_with_policy(&manifest, &test_request(), &policy)
            .expect_err("policy default timeout should apply");
        let message = error.to_string();
        assert!(message.contains("exceeded timeout_ms=50"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_no_timeout_manifest_without_policy_opt_in() {
        let (dir, _script_path) = write_plugin_script("#!/bin/sh\nprintf '{\"ok\":true}\\n'\n");
        let manifest = PluginManifest {
            name: "no-timeout".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["plugin.sh".to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: Some(0),
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let error = run_plugin(&manifest, &test_request()).expect_err("no timeout should reject");
        let message = error.to_string();
        assert!(message.contains("timeout_ms=0"), "{message}");
        assert!(message.contains("disables the plugin timeout"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn allows_no_timeout_when_policy_opts_in() {
        let (dir, _script_path) = write_plugin_script(
            "#!/bin/sh\nsleep 0.1\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n",
        );
        let manifest = PluginManifest {
            name: "trusted-no-timeout".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["plugin.sh".to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: Some(0),
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let policy = PluginExecutionPolicy::default().with_allow_no_timeout(true);
        let response = run_plugin_with_policy(&manifest, &test_request(), &policy)
            .expect("trusted no-timeout plugin should succeed");
        assert!(response.ok);
        assert_eq!(response.extra.get("features"), Some(&json!({"value": 1})));
    }

    #[cfg(unix)]
    #[test]
    fn allows_known_interpreter_for_manifest_local_script() {
        let (dir, _script_path) = write_plugin_script(
            "#!/bin/sh\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n",
        );
        let manifest = PluginManifest {
            name: "shell-wrapper".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["sh".to_string(), "plugin.sh".to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let response = run_plugin(&manifest, &test_request())
            .expect("known interpreter with manifest-local script should succeed");
        assert!(response.ok);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_bare_path_lookup_by_default() {
        let dir = tempdir().expect("tempdir");
        let manifest = PluginManifest {
            name: "path-command".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["logicpearl-plugin-not-in-manifest".to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let error = run_plugin(&manifest, &test_request()).expect_err("PATH lookup should reject");
        let message = error.to_string();
        assert!(message.contains("PATH lookup is disabled"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_absolute_entrypoint_by_default() {
        let (dir, script_path) = write_plugin_script(
            "#!/bin/sh\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n",
        );
        let manifest = PluginManifest {
            name: "absolute".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec![script_path.display().to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let error =
            run_plugin(&manifest, &test_request()).expect_err("absolute entrypoint should reject");
        let message = error.to_string();
        assert!(message.contains("absolute program path"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn allows_absolute_entrypoint_when_policy_opts_in() {
        let (dir, script_path) = write_plugin_script(
            "#!/bin/sh\nprintf '{\"ok\":true,\"features\":{\"value\":1}}\\n'\n",
        );
        let manifest = PluginManifest {
            name: "absolute".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec![script_path.display().to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: None,
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let policy = PluginExecutionPolicy::default().with_allow_absolute_entrypoint(true);
        let response = run_plugin_with_policy(&manifest, &test_request(), &policy)
            .expect("absolute entrypoint should run only under explicit policy");
        assert!(response.ok);
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_descendants_that_keep_output_pipes_open() {
        let (dir, _script_path) = write_plugin_script(
            "#!/bin/sh\n(sh -c 'sleep 5') &\nsleep 5\nprintf '{\"ok\":true}\\n'\n",
        );
        let manifest = PluginManifest {
            name: "tree".to_string(),
            protocol_version: "1".to_string(),
            stage: PluginStage::Observer,
            entrypoint: vec!["plugin.sh".to_string()],
            language: Some("shell".to_string()),
            capabilities: None,
            timeout_ms: Some(50),
            input_schema: None,
            options_schema: None,
            output_schema: None,
            manifest_dir: Some(dir.path().to_path_buf()),
        };

        let started_at = std::time::Instant::now();
        let error = run_plugin(&manifest, &test_request()).expect_err("plugin should time out");
        assert!(
            started_at.elapsed() < std::time::Duration::from_secs(2),
            "timeout should not wait for descendant sleep process"
        );
        let message = error.to_string();
        assert!(message.contains("exceeded timeout_ms=50"), "{message}");
    }

    #[test]
    fn limited_reader_rejects_outputs_above_cap() {
        let mut reader = std::io::Cursor::new(vec![b'x'; 5]);
        let error = super::read_limited(&mut reader, 4).expect_err("reader should reject overflow");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), 5, "reader should drain capped streams");
    }
}
