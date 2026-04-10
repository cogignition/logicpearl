use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SOLVER_BACKEND_ENV: &str = "LOGICPEARL_SOLVER_BACKEND";
pub const SOLVER_TIMEOUT_MS_ENV: &str = "LOGICPEARL_SOLVER_TIMEOUT_MS";
pub const SOLVER_DIR_ENV: &str = "LOGICPEARL_SOLVER_DIR";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBackend {
    Z3,
    Cvc5,
}

impl SolverBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Z3 => "z3",
            Self::Cvc5 => "cvc5",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SolverMode {
    #[default]
    Auto,
    Prefer(SolverBackend),
    Require(SolverBackend),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SolverSettings {
    pub mode: SolverMode,
    pub timeout_ms: Option<u64>,
}

impl SolverSettings {
    pub fn from_env() -> Result<Self> {
        let mut settings = Self::default();

        if let Some(raw_backend) = env_override(SOLVER_BACKEND_ENV) {
            settings.mode = parse_solver_mode(&raw_backend)?;
        }

        if let Some(raw_timeout) = env_override(SOLVER_TIMEOUT_MS_ENV) {
            settings.timeout_ms = Some(raw_timeout.parse::<u64>().map_err(|err| {
                LogicPearlError::message(format!(
                    "{SOLVER_TIMEOUT_MS_ENV} must be an integer timeout in milliseconds: {err}"
                ))
            })?);
        }

        Ok(settings)
    }
}

fn env_override(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    })
}

fn parse_solver_mode(raw: &str) -> Result<SolverMode> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "auto" => Ok(SolverMode::Auto),
        "z3" => Ok(SolverMode::Require(SolverBackend::Z3)),
        "cvc5" => Ok(SolverMode::Require(SolverBackend::Cvc5)),
        "prefer-z3" | "prefer_z3" => Ok(SolverMode::Prefer(SolverBackend::Z3)),
        "prefer-cvc5" | "prefer_cvc5" => Ok(SolverMode::Prefer(SolverBackend::Cvc5)),
        other => Err(LogicPearlError::message(format!(
            "unsupported solver backend override `{other}` in {SOLVER_BACKEND_ENV}; expected one of auto, z3, cvc5, prefer-z3, prefer-cvc5"
        ))),
    }
}

pub fn resolve_backend(settings: &SolverSettings) -> Result<SolverBackend> {
    resolve_backend_with_probe(settings, is_backend_available)
}

pub fn is_backend_available(backend: SolverBackend) -> bool {
    resolve_backend_binary(backend).is_some()
}

fn resolve_backend_with_probe(
    settings: &SolverSettings,
    probe: impl Fn(SolverBackend) -> bool,
) -> Result<SolverBackend> {
    let candidates = preferred_backends(settings.mode);
    for backend in candidates {
        if probe(backend) {
            return Ok(backend);
        }
    }

    match settings.mode {
        SolverMode::Require(backend) => Err(LogicPearlError::message(format!(
            "required solver backend {} was not found on PATH",
            backend.as_str()
        ))),
        _ => Err(LogicPearlError::message(
            "no supported solver backend was found on PATH; install z3 or cvc5, or set LOGICPEARL_SOLVER_BACKEND to a supported value",
        )),
    }
}

fn preferred_backends(mode: SolverMode) -> [SolverBackend; 2] {
    match mode {
        SolverMode::Auto | SolverMode::Prefer(SolverBackend::Z3) => {
            [SolverBackend::Z3, SolverBackend::Cvc5]
        }
        SolverMode::Prefer(SolverBackend::Cvc5) => [SolverBackend::Cvc5, SolverBackend::Z3],
        SolverMode::Require(backend) => [backend, backend],
    }
}

fn resolve_backend_binary(backend: SolverBackend) -> Option<PathBuf> {
    let solver_dir = env_override(SOLVER_DIR_ENV).map(PathBuf::from);
    let current_exe = env::current_exe().ok();
    resolve_backend_binary_with_sources(
        backend,
        solver_dir.as_deref(),
        current_exe.as_deref().and_then(Path::parent),
        binary_on_path,
    )
}

fn resolve_backend_binary_with_sources(
    backend: SolverBackend,
    solver_dir: Option<&Path>,
    executable_dir: Option<&Path>,
    path_lookup: impl Fn(&str) -> bool,
) -> Option<PathBuf> {
    let binary = backend.as_str();
    solver_dir
        .into_iter()
        .chain(executable_dir)
        .find_map(|directory| {
            candidate_paths(directory, binary)
                .into_iter()
                .find(|path| path.is_file())
        })
        .or_else(|| path_lookup(binary).then(|| PathBuf::from(binary)))
}

fn binary_on_path(binary: &str) -> bool {
    if binary.contains(std::path::MAIN_SEPARATOR) {
        return Path::new(binary).exists();
    }

    env::var_os("PATH")
        .as_deref()
        .map(env::split_paths)
        .into_iter()
        .flatten()
        .any(|directory| {
            candidate_paths(&directory, binary)
                .into_iter()
                .any(|path| path.is_file())
        })
}

fn candidate_paths(directory: &Path, binary: &str) -> Vec<PathBuf> {
    let candidates = vec![directory.join(binary)];
    #[cfg(windows)]
    if Path::new(binary).extension().is_none() {
        let mut candidates = candidates;
        candidates.push(directory.join(format!("{binary}.exe")));
        return candidates;
    }
    candidates
}

pub(crate) fn command_for_backend(
    backend: SolverBackend,
    script_path: &Path,
    timeout_ms: Option<u64>,
    needs_model: bool,
) -> Command {
    let solver_binary =
        resolve_backend_binary(backend).unwrap_or_else(|| PathBuf::from(backend.as_str()));
    let mut command = Command::new(solver_binary);
    match backend {
        SolverBackend::Z3 => {
            if let Some(timeout_ms) = timeout_ms.filter(|timeout| *timeout > 0) {
                let timeout_seconds = timeout_ms.div_ceil(1000).max(1);
                command.arg(format!("-T:{timeout_seconds}"));
            }
            command.arg("-smt2").arg(script_path);
        }
        SolverBackend::Cvc5 => {
            if let Some(timeout_ms) = timeout_ms.filter(|timeout| *timeout > 0) {
                command.arg(format!("--tlimit={timeout_ms}"));
            }
            if needs_model {
                command.arg("--produce-models");
            }
            command.arg("--lang=smt2").arg(script_path);
        }
    }
    command
}

#[cfg(test)]
mod tests {
    use super::{
        command_for_backend, is_backend_available, resolve_backend_binary_with_sources,
        resolve_backend_with_probe, SolverBackend, SolverMode, SolverSettings, SOLVER_BACKEND_ENV,
        SOLVER_DIR_ENV, SOLVER_TIMEOUT_MS_ENV,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_env_vars(vars: &[(&str, Option<&str>)], test: impl FnOnce()) {
        let _guard = env_lock().lock().expect("env lock should be available");
        let saved = vars
            .iter()
            .map(|(name, _)| ((*name).to_string(), std::env::var(name).ok()))
            .collect::<Vec<_>>();
        for (name, value) in vars {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        test();
        for (name, value) in saved {
            match value {
                Some(value) => std::env::set_var(&name, value),
                None => std::env::remove_var(&name),
            }
        }
    }

    fn write_fake_solver(dir: &TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("fake solver should be written");
        path
    }

    #[test]
    fn prefer_cvc5_falls_back_to_z3_when_cvc5_is_unavailable() {
        let backend = resolve_backend_with_probe(
            &SolverSettings {
                mode: SolverMode::Prefer(SolverBackend::Cvc5),
                timeout_ms: None,
            },
            |backend| matches!(backend, SolverBackend::Z3),
        )
        .expect("prefer should fall back to z3 when cvc5 is unavailable");
        assert_eq!(backend, SolverBackend::Z3);
    }

    #[test]
    fn auto_uses_cvc5_when_z3_is_unavailable() {
        let backend = resolve_backend_with_probe(
            &SolverSettings {
                mode: SolverMode::Auto,
                timeout_ms: None,
            },
            |backend| matches!(backend, SolverBackend::Cvc5),
        )
        .expect("auto should fall back to cvc5 when z3 is unavailable");
        assert_eq!(backend, SolverBackend::Cvc5);
    }

    #[test]
    fn require_cvc5_succeeds_when_available() {
        let backend = resolve_backend_with_probe(
            &SolverSettings {
                mode: SolverMode::Require(SolverBackend::Cvc5),
                timeout_ms: None,
            },
            |backend| matches!(backend, SolverBackend::Cvc5),
        )
        .expect("require cvc5 should succeed when cvc5 is available");
        assert_eq!(backend, SolverBackend::Cvc5);
    }

    #[test]
    fn require_cvc5_is_rejected_when_unavailable() {
        let err = resolve_backend_with_probe(
            &SolverSettings {
                mode: SolverMode::Require(SolverBackend::Cvc5),
                timeout_ms: None,
            },
            |_| false,
        )
        .expect_err("require cvc5 should fail when cvc5 is unavailable");
        assert!(err.to_string().contains("cvc5"));
    }

    #[test]
    fn reads_backend_and_timeout_from_environment() {
        with_env_vars(
            &[
                (SOLVER_BACKEND_ENV, Some("prefer-cvc5")),
                (SOLVER_TIMEOUT_MS_ENV, Some("2500")),
            ],
            || {
                let settings = SolverSettings::from_env().expect("env overrides should parse");
                assert_eq!(settings.mode, SolverMode::Prefer(SolverBackend::Cvc5));
                assert_eq!(settings.timeout_ms, Some(2_500));
            },
        );
    }

    #[test]
    fn bundled_solver_dir_override_is_checked_before_path() {
        let temp = TempDir::new().expect("temp dir should exist");
        let z3_path = write_fake_solver(&temp, "z3");
        with_env_vars(
            &[(SOLVER_DIR_ENV, Some(temp.path().to_str().unwrap()))],
            || {
                assert!(is_backend_available(SolverBackend::Z3));
            },
        );
        assert!(z3_path.exists());
    }

    #[test]
    fn bundled_current_exe_directory_is_checked_before_path() {
        let temp = TempDir::new().expect("temp dir should exist");
        let exe_path = temp.path().join("logicpearl");
        fs::write(&exe_path, b"binary").expect("fake executable should be written");
        let z3_path = write_fake_solver(&temp, "z3");

        let resolved =
            resolve_backend_binary_with_sources(SolverBackend::Z3, None, exe_path.parent(), |_| {
                false
            })
            .expect("bundled solver path should resolve");

        assert_eq!(resolved, z3_path);
    }

    #[test]
    fn explicit_solver_dir_wins_over_executable_directory() {
        let solver_dir = TempDir::new().expect("solver dir should exist");
        let exe_dir = TempDir::new().expect("exe dir should exist");
        let preferred = write_fake_solver(&solver_dir, "z3");
        let _fallback = write_fake_solver(&exe_dir, "z3");

        let resolved = resolve_backend_binary_with_sources(
            SolverBackend::Z3,
            Some(solver_dir.path()),
            Some(exe_dir.path()),
            |_| false,
        )
        .expect("solver dir should win over executable directory");

        assert_eq!(resolved, preferred);
    }

    #[test]
    fn rejects_unknown_backend_override() {
        with_env_vars(&[(SOLVER_BACKEND_ENV, Some("wat"))], || {
            let err = SolverSettings::from_env().expect_err("unknown backend override should fail");
            assert!(err.to_string().contains(SOLVER_BACKEND_ENV));
        });
    }

    #[test]
    fn rejects_non_numeric_timeout_override() {
        with_env_vars(&[(SOLVER_TIMEOUT_MS_ENV, Some("fast"))], || {
            let err =
                SolverSettings::from_env().expect_err("non-numeric timeout override should fail");
            assert!(err.to_string().contains(SOLVER_TIMEOUT_MS_ENV));
        });
    }

    #[test]
    fn z3_command_uses_seconds_timeout_and_smt2_mode() {
        let command = command_for_backend(
            SolverBackend::Z3,
            Path::new("/tmp/example.smt2"),
            Some(2_500),
            false,
        );
        assert_eq!(command.get_program().to_string_lossy(), "z3");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["-T:3", "-smt2", "/tmp/example.smt2"]);
    }

    #[test]
    fn cvc5_command_enables_models_and_uses_millisecond_timeout() {
        let command = command_for_backend(
            SolverBackend::Cvc5,
            Path::new("/tmp/example.smt2"),
            Some(2_500),
            true,
        );
        assert_eq!(command.get_program().to_string_lossy(), "cvc5");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                "--tlimit=2500",
                "--produce-models",
                "--lang=smt2",
                "/tmp/example.smt2"
            ]
        );
    }
}
