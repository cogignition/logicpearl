use pearl_runtime::ir::{LogicPearlGateIr, RuleVerificationStatus};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Err("missing subcommand".into());
    }

    match args[1].as_str() {
        "build" => run_build(&args[2..]),
        "run" => run_eval(&args[2..]),
        "inspect" => run_inspect(&args[2..]),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("unknown subcommand: {other}").into()),
    }
}

fn run_build(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("usage: logicpearl build <decision_traces.csv> [--output-dir <dir>] [--gate-id <id>] [--label-column <name>]".into());
    }

    let decision_traces = PathBuf::from(&args[0]);
    let mut passthrough: Vec<String> = Vec::new();
    passthrough.push(decision_traces.display().to_string());
    passthrough.extend(args.iter().skip(1).cloned());

    let discovery_dir = runtime_dir().parent().ok_or("failed to locate discovery workspace")?.join("discovery");
    let status = Command::new("uv")
        .arg("run")
        .arg("--project")
        .arg(&discovery_dir)
        .arg("logicpearl-build-pearl")
        .args(&passthrough)
        .status()?;

    if !status.success() {
        return Err(format!("logicpearl-build-pearl exited with status {status}").into());
    }
    Ok(())
}

fn run_eval(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 2 {
        return Err("usage: logicpearl run <pearl.ir.json> <input.json>".into());
    }

    let gate = LogicPearlGateIr::from_path(&args[0])?;
    let content = fs::read_to_string(&args[1])?;
    let payload: Value = serde_json::from_str(&content)?;

    match payload {
        Value::Object(object) => {
            let input = object_to_features(&object);
            let bitmask = gate.evaluate(&input)?;
            println!("{bitmask}");
        }
        Value::Array(items) => {
            let mut bitmasks = Vec::with_capacity(items.len());
            for item in items {
                let object = item
                    .as_object()
                    .ok_or("input JSON array must contain only feature objects")?;
                let input = object_to_features(object);
                let bitmask = gate.evaluate(&input)?;
                bitmasks.push(bitmask);
            }
            println!("{}", serde_json::to_string_pretty(&bitmasks)?);
        }
        _ => {
            return Err("input JSON must be an object or an array of feature objects".into());
        }
    }
    Ok(())
}

fn run_inspect(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 1 {
        return Err("usage: logicpearl inspect <pearl.ir.json>".into());
    }

    let gate = LogicPearlGateIr::from_path(&args[0])?;
    println!("Gate ID: {}", gate.gate_id);
    println!("IR version: {}", gate.ir_version);
    println!("Features: {}", gate.input_schema.features.len());
    println!("Rules: {}", gate.rules.len());
    if let Some(verification) = &gate.verification {
        if let Some(scope) = &verification.correctness_scope {
            println!("Correctness scope: {scope}");
        }
        if let Some(summary) = &verification.verification_summary {
            println!("Verification summary:");
            for (key, value) in summary {
                println!("  {key}: {value}");
            }
        }
    }
    println!("Rule details:");
    for rule in &gate.rules {
        let status = match &rule.verification_status {
            Some(RuleVerificationStatus::Z3Verified) => "z3_verified",
            Some(RuleVerificationStatus::PipelineUnverified) => "pipeline_unverified",
            Some(RuleVerificationStatus::HeuristicUnverified) => "heuristic_unverified",
            Some(RuleVerificationStatus::RefinedUnverified) => "refined_unverified",
            None => "unknown",
        };
        println!("  bit {}: {} [{}]", rule.bit, rule.id, status);
    }
    Ok(())
}

fn object_to_features(object: &serde_json::Map<String, Value>) -> HashMap<String, Value> {
    let mut features = HashMap::new();
    for (key, value) in object {
        features.insert(key.clone(), value.clone());
    }
    features
}

fn runtime_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn print_usage() {
    eprintln!(
        "usage:\n  logicpearl build <decision_traces.csv> [--output-dir <dir>] [--gate-id <id>] [--label-column <name>]\n  logicpearl run <pearl.ir.json> <input.json>\n  logicpearl inspect <pearl.ir.json>"
    );
}
