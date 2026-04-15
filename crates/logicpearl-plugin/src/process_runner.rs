// SPDX-License-Identifier: MIT
use super::provenance::{
    build_plugin_run_metadata, now_utc_rfc3339, PluginRunMetadata, PluginRunMetadataInputs,
};
use super::{PluginExecutionPolicy, PluginManifest};
use logicpearl_core::{LogicPearlError, Result};
use serde::Serialize;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PLUGIN_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PLUGIN_STDERR_BYTES: usize = 8 * 1024 * 1024;
const PLUGIN_SPAWN_TEXT_BUSY_RETRIES: usize = 5;
const PLUGIN_SPAWN_TEXT_BUSY_BACKOFF_MS: u64 = 20;
#[cfg(unix)]
use libc::{getpgid, getpgrp, kill, SIGKILL, SIGTERM};

pub(crate) struct RawPluginRun {
    pub(crate) stdout: String,
    pub(crate) metadata: PluginRunMetadata,
}

pub(crate) fn run_plugin_raw<T: Serialize>(
    manifest: &PluginManifest,
    request: &T,
    policy: &PluginExecutionPolicy,
) -> Result<RawPluginRun> {
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

    let request_value = serde_json::to_value(request).map_err(LogicPearlError::from)?;
    let timeout_ms = effective_timeout_ms(manifest, policy)?;
    let started_at = now_utc_rfc3339();
    let started = Instant::now();
    let mut child = spawn_plugin_process(&mut command)?;
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

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| LogicPearlError::message("failed to open plugin stdin"))?;
    let payload = serde_json::to_vec(request)?;
    write_plugin_stdin(&mut stdin, &payload)?;
    drop(stdin);

    let (status, timed_out) = wait_for_plugin_exit(timeout_ms, &mut child)?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let completed_at = now_utc_rfc3339();
    let stdout = join_pipe_reader(manifest, "stdout", stdout_handle)?;
    let stderr = join_pipe_reader(manifest, "stderr", stderr_handle)?;
    let stderr_display = String::from_utf8_lossy(&stderr).trim().to_string();

    if timed_out {
        let timeout_display = timeout_ms.unwrap_or_default();
        return Err(LogicPearlError::message(format!(
            "plugin {} exceeded timeout_ms={} and was terminated{}",
            manifest.name,
            timeout_display,
            if stderr_display.is_empty() {
                String::new()
            } else {
                format!(": {stderr_display}")
            }
        )));
    }

    if !status.success() {
        return Err(LogicPearlError::message(format!(
            "plugin {} exited with status {}{}",
            manifest.name,
            status,
            if stderr_display.is_empty() {
                String::new()
            } else {
                format!(": {stderr_display}")
            }
        )));
    }

    let metadata = build_plugin_run_metadata(PluginRunMetadataInputs {
        manifest,
        policy,
        resolved_entrypoint: &entrypoint,
        request_value: &request_value,
        stdout: stdout.clone(),
        stderr,
        effective_timeout_ms: timeout_ms,
        started_at,
        completed_at,
        duration_ms,
    })?;
    let stdout = String::from_utf8(stdout).map_err(|err| {
        LogicPearlError::message(format!(
            "plugin {} returned invalid UTF-8: {}",
            manifest.name, err
        ))
    })?;
    Ok(RawPluginRun { stdout, metadata })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPluginEntrypoint {
    program: String,
    args: Vec<String>,
}

impl ResolvedPluginEntrypoint {
    pub(crate) fn segments(&self) -> Vec<String> {
        std::iter::once(self.program.clone())
            .chain(self.args.iter().cloned())
            .collect()
    }
}

pub(crate) fn resolve_entrypoint(
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

pub(crate) fn effective_timeout_ms(
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

pub(crate) fn write_plugin_stdin(stdin: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    write_plugin_stdin_chunk(stdin, payload)?;
    write_plugin_stdin_chunk(stdin, b"\n")
}

fn write_plugin_stdin_chunk(stdin: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    match stdin.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error),
    }
}

fn spawn_limited_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || read_limited(&mut reader, max_bytes))
}

pub(crate) fn read_limited(reader: &mut impl Read, max_bytes: usize) -> std::io::Result<Vec<u8>> {
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
    const MAX_POLL_INTERVAL: Duration = Duration::from_millis(200);

    if let Some(timeout_ms) = timeout_ms {
        let timeout = Duration::from_millis(timeout_ms);
        let started_at = Instant::now();
        let mut poll_interval = Duration::from_millis(10);
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, false));
            }
            if started_at.elapsed() >= timeout {
                terminate_plugin_process(child);
                let status = child.wait()?;
                return Ok((status, true));
            }
            thread::sleep(poll_interval);
            poll_interval = (poll_interval * 2).min(MAX_POLL_INTERVAL);
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
