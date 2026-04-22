// SPDX-License-Identifier: MIT
//! Thread-local persistent Z3 workers.
//!
//! The previous model spawned a fresh `z3 -smt2 <file>` subprocess per query
//! and read its output with `Command::output()`. Under concurrent discovery
//! (12 lookahead threads × many synthesis calls per pass) the pipe FDs
//! created for one worker's spawn could be inherited by a sibling worker's
//! `posix_spawn` before the original `exec` set `O_CLOEXEC`, leaving the
//! write end of the pipe held open inside the unrelated child. When the
//! intended Z3 exited, `read_output()`'s `poll()` never observed EOF,
//! parking the worker thread forever. At trace counts >500 this deadlock
//! became reproducible on every run.
//!
//! The fix here: hold one long-lived Z3 process per caller thread and feed
//! it SMT-LIB commands over stdin. No per-query `fork`/`exec`, no per-query
//! pipe allocation, no FD-inheritance race. Between queries we issue
//! `(reset)` so each call starts from a clean context, and we bracket
//! every query with a `(echo …)` sentinel so the reader knows when that
//! query's stdout is complete. Per-query wall-clock is enforced via
//! `(set-option :timeout N)` which Z3 applies to the subsequent
//! `check-sat`.
//!
//! Only Z3 is pooled today. CVC5 still uses the spawn-per-query path
//! because its interactive mode has a different surface; it isn't what we
//! run under concurrency today, so the race doesn't trigger.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use logicpearl_core::{LogicPearlError, Result};

use crate::backend::{resolve_backend_binary, SolverBackend};
use crate::parse::parse_sat_status;
use crate::{RawSolverOutput, SatStatus};

const QUERY_END_SENTINEL: &str = "__LP_QUERY_END__";
const READ_GRACE_AFTER_TIMEOUT: Duration = Duration::from_millis(2000);

struct Z3Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Z3Worker {
    fn spawn() -> Result<Self> {
        let binary = resolve_backend_binary(SolverBackend::Z3)
            .unwrap_or_else(|| std::path::PathBuf::from(SolverBackend::Z3.as_str()));
        let mut child = Command::new(binary)
            .arg("-smt2")
            .arg("-in")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                LogicPearlError::message(format!("failed to launch z3 worker: {err}"))
            })?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
        let mut worker = Self {
            child,
            stdin,
            stdout,
        };
        // Silence per-command `success` acks so stdout contains only
        // responses we care about (check-sat, get-model, echo, errors).
        writeln!(worker.stdin, "(set-option :print-success false)")
            .map_err(|err| LogicPearlError::message(format!("z3 handshake write failed: {err}")))?;
        Ok(worker)
    }

    fn run_query(&mut self, script: &str, timeout_ms: Option<u64>) -> Result<RawSolverOutput> {
        // Clean slate. `(reset)` drops all declarations, assertions, and
        // options except those we re-set below.
        writeln!(self.stdin, "(reset)")
            .map_err(|err| LogicPearlError::message(format!("z3 write failed: {err}")))?;
        writeln!(self.stdin, "(set-option :print-success false)")
            .map_err(|err| LogicPearlError::message(format!("z3 write failed: {err}")))?;
        if let Some(ms) = timeout_ms.filter(|ms| *ms > 0) {
            writeln!(self.stdin, "(set-option :timeout {ms})")
                .map_err(|err| LogicPearlError::message(format!("z3 write failed: {err}")))?;
        }
        self.stdin
            .write_all(script.as_bytes())
            .map_err(|err| LogicPearlError::message(format!("z3 write failed: {err}")))?;
        if !script.ends_with('\n') {
            self.stdin
                .write_all(b"\n")
                .map_err(|err| LogicPearlError::message(format!("z3 write failed: {err}")))?;
        }
        writeln!(self.stdin, "(echo \"{QUERY_END_SENTINEL}\")")
            .map_err(|err| LogicPearlError::message(format!("z3 write failed: {err}")))?;
        self.stdin
            .flush()
            .map_err(|err| LogicPearlError::message(format!("z3 flush failed: {err}")))?;

        // Read until we see our sentinel on its own line. Upper-bound the
        // wait to `timeout + grace`: if Z3 honored its own `:timeout`, it
        // must have emitted something and released us before then. If it
        // hasn't, the worker is considered wedged and is discarded by the
        // caller.
        let deadline = timeout_ms
            .map(|ms| Instant::now() + Duration::from_millis(ms) + READ_GRACE_AFTER_TIMEOUT);
        let mut stdout_buf = String::new();
        let mut line = String::new();
        loop {
            if let Some(deadline) = deadline {
                if Instant::now() > deadline {
                    return Err(LogicPearlError::message(
                        "z3 worker exceeded wall-clock deadline",
                    ));
                }
            }
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .map_err(|err| LogicPearlError::message(format!("z3 read failed: {err}")))?;
            if n == 0 {
                return Err(LogicPearlError::message("z3 worker closed stdout"));
            }
            if line.trim() == QUERY_END_SENTINEL {
                break;
            }
            stdout_buf.push_str(&line);
        }

        let status = parse_sat_status(&stdout_buf)?;
        Ok(RawSolverOutput {
            backend_used: SolverBackend::Z3,
            status,
            stdout: stdout_buf,
            stderr: String::new(),
            exit_code: None,
        })
    }
}

impl Drop for Z3Worker {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "(exit)");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

thread_local! {
    static WORKER_SLOT: RefCell<Option<Z3Worker>> = const { RefCell::new(None) };
}

/// Run a Z3 SMT script through the caller thread's persistent worker,
/// spawning one on first use. On any I/O failure (which we treat as the
/// worker being wedged or crashed) we retry exactly once with a fresh
/// process so a transient Z3 OOM or a ragged exit doesn't poison the
/// whole build.
pub(crate) fn run_z3_script_pooled(
    script: &str,
    timeout_ms: Option<u64>,
) -> Result<RawSolverOutput> {
    const MAX_RETRIES: u32 = 1;
    for attempt in 0..=MAX_RETRIES {
        let outcome = WORKER_SLOT.with(|cell| {
            let mut borrowed = cell.borrow_mut();
            if borrowed.is_none() {
                match Z3Worker::spawn() {
                    Ok(worker) => *borrowed = Some(worker),
                    Err(err) => return Err(err),
                }
            }
            let worker = borrowed.as_mut().expect("worker present");
            let result = worker.run_query(script, timeout_ms);
            if result.is_err() {
                // Discard the worker. Next call spawns a fresh one.
                *borrowed = None;
            }
            result
        });
        match outcome {
            Ok(raw) => {
                // An `unknown` status can mean "Z3 hit its self-enforced
                // timeout" — that's a fine per-query outcome, no retry.
                if raw.status == SatStatus::Unknown && !raw.stdout.contains("error") {
                    return Ok(raw);
                }
                return Ok(raw);
            }
            Err(err) => {
                if attempt == MAX_RETRIES {
                    return Err(err);
                }
                // else: fall through and retry with a fresh worker
            }
        }
    }
    unreachable!("loop returns on every path")
}
