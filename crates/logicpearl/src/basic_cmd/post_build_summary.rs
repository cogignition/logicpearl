// SPDX-License-Identifier: MIT

use anstream::println;
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};

pub(super) struct PostBuildSummary {
    pub(super) artifact_kind: &'static str,
    pub(super) artifact_name: String,
    pub(super) learned: Vec<String>,
    pub(super) metrics: Vec<(String, String)>,
    pub(super) recommendations: Vec<String>,
    pub(super) top_rules: Vec<String>,
    pub(super) bundle_path: PathBuf,
    pub(super) entrypoint_path: PathBuf,
    pub(super) ir_path: Option<PathBuf>,
    pub(super) report_path: Option<PathBuf>,
    pub(super) extra_files: Vec<(String, PathBuf)>,
    pub(super) compile_requested: bool,
    pub(super) wasm_skipped: bool,
}

impl PostBuildSummary {
    pub(super) fn render(&self) {
        println!(
            "{} {} {}",
            "Built".bold().bright_green(),
            self.artifact_kind,
            self.artifact_name.bold()
        );
        print_section("Learned", &self.learned);
        print_pairs("Metrics", &self.metrics);
        print_section("Recommendations", &self.recommendations);
        print_numbered_section("Top rules", &self.top_rules);
        self.print_bundle();
        self.print_next_commands();
    }

    fn print_bundle(&self) {
        println!("\n{}", "Bundle".bold());
        println!("  Entry: {}", self.entrypoint_path.display());
        println!("  Directory: {}", self.bundle_path.display());
        if let Some(ir_path) = &self.ir_path {
            println!("  IR: {}", ir_path.display());
        }
        if let Some(report_path) = &self.report_path {
            println!("  Report: {}", report_path.display());
        }
        for (label, path) in &self.extra_files {
            println!("  {label}: {}", path.display());
        }
        if self.wasm_skipped {
            println!("  Wasm: skipped; install wasm32-unknown-unknown to emit it");
        } else if !self.compile_requested {
            println!("  Deployables: not compiled yet");
        }
    }

    fn print_next_commands(&self) {
        let artifact = shell_arg(&self.entrypoint_path);
        println!("\n{}", "Next commands".bold());
        println!("  Run: logicpearl run {artifact} input.json --json");
        println!("  Inspect: logicpearl inspect {artifact}");
        println!("  Diff: logicpearl diff old_artifact {artifact} --json");
        println!("  Compile: logicpearl compile {artifact}");
        println!("  Verify: logicpearl artifact verify {artifact} --json");
    }
}

pub(super) fn percent(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

pub(super) fn top_rule_lines<I>(rules: I, limit: usize) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut out = rules
        .into_iter()
        .filter(|line| !line.trim().is_empty())
        .take(limit)
        .collect::<Vec<_>>();
    if out.is_empty() {
        out.push("No learned rules were emitted; runtime uses the configured default.".to_string());
    }
    out
}

fn print_section(title: &str, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    println!("\n{}", title.bold());
    for line in lines {
        println!("  - {line}");
    }
}

fn print_pairs(title: &str, pairs: &[(String, String)]) {
    println!("\n{}", title.bold());
    for (label, value) in pairs {
        println!("  - {label}: {value}");
    }
}

fn print_numbered_section(title: &str, lines: &[String]) {
    println!("\n{}", title.bold());
    for (index, line) in lines.iter().enumerate() {
        println!("  {}. {line}", index + 1);
    }
}

pub(super) fn shell_arg(path: &Path) -> String {
    let value = path.display().to_string();
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | ','))
    {
        value
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
