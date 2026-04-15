// SPDX-License-Identifier: MIT
use super::{sanitize_identifier, BenchmarkAdaptDefaults, BenchmarkCase};
use logicpearl_core::{LogicPearlError, Result};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
struct MtAgentRiskTurnsFile {
    turns: Vec<MtAgentRiskTurnEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct MtAgentRiskTurnEntry {
    instruction_file: String,
}

pub fn adapt_mt_agentrisk_dataset(
    dataset_root: &Path,
    defaults: &BenchmarkAdaptDefaults,
) -> Result<Vec<BenchmarkCase>> {
    if !is_mt_agentrisk_root(dataset_root) {
        return Err(LogicPearlError::message(format!(
            "MT-AgentRisk dataset root is missing expected markers: {}",
            dataset_root.display()
        )));
    }

    let workspaces_root = dataset_root.join("workspaces");
    let mut cases = Vec::new();

    for tool_dir in sorted_child_dirs(&workspaces_root)? {
        let tool_name = tool_dir
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown");
        if tool_name == "benign_tasks" {
            continue;
        }

        let single_turn_root = tool_dir.join("single-turn-tasks");
        if single_turn_root.is_dir() {
            for task_dir in sorted_child_dirs(&single_turn_root)? {
                let prompt = read_trimmed_text(&task_dir.join("task.md"))?;
                cases.push(build_mt_agentrisk_case(
                    format!(
                        "mt_agentrisk_single_{}_{}",
                        sanitize_identifier(tool_name),
                        sanitize_identifier(
                            task_dir
                                .file_name()
                                .and_then(|value| value.to_str())
                                .unwrap_or("task")
                        )
                    ),
                    prompt,
                    "deny",
                    format!("mt-agentrisk:single-turn-harmful:{tool_name}"),
                    defaults,
                    serde_json::json!({
                        "mt_agentrisk_tool": tool_name,
                        "mt_agentrisk_variant": "single-turn-harmful",
                        "mt_agentrisk_turn_count": 1,
                    }),
                ));
            }
        }

        let multi_turn_root = tool_dir.join("multi-turn-tasks");
        if multi_turn_root.is_dir() {
            for task_dir in sorted_child_dirs(&multi_turn_root)? {
                let turns_path = task_dir.join("turns.yml");
                if !turns_path.is_file() {
                    continue;
                }
                let turns = load_mt_agentrisk_turns(&turns_path)?;
                let prompt = render_mt_agentrisk_multi_turn_prompt(&turns);
                let turn_values = turns
                    .iter()
                    .enumerate()
                    .map(|(index, turn)| {
                        serde_json::json!({
                            "turn_index": index + 1,
                            "prompt": turn,
                        })
                    })
                    .collect::<Vec<_>>();
                cases.push(build_mt_agentrisk_case(
                    format!(
                        "mt_agentrisk_multi_{}_{}",
                        sanitize_identifier(tool_name),
                        sanitize_identifier(
                            task_dir
                                .file_name()
                                .and_then(|value| value.to_str())
                                .unwrap_or("task")
                        )
                    ),
                    prompt,
                    "deny",
                    format!("mt-agentrisk:multi-turn-harmful:{tool_name}"),
                    defaults,
                    serde_json::json!({
                        "mt_agentrisk_tool": tool_name,
                        "mt_agentrisk_variant": "multi-turn-harmful",
                        "mt_agentrisk_turn_count": turn_values.len(),
                        "conversation_turns": turn_values,
                    }),
                ));
            }
        }
    }

    let benign_root = workspaces_root.join("benign_tasks");
    if benign_root.is_dir() {
        for tool_group in sorted_child_dirs(&benign_root)? {
            let tool_name = tool_group
                .file_name()
                .and_then(|value| value.to_str())
                .map(|value| value.strip_prefix("benign_tasks_").unwrap_or(value))
                .unwrap_or("unknown");
            for task_dir in sorted_child_dirs(&tool_group)? {
                let task_path = task_dir.join("task.md");
                if !task_path.is_file() {
                    continue;
                }
                let prompt = read_trimmed_text(&task_path)?;
                cases.push(build_mt_agentrisk_case(
                    format!(
                        "mt_agentrisk_benign_{}_{}",
                        sanitize_identifier(tool_name),
                        sanitize_identifier(
                            task_dir
                                .file_name()
                                .and_then(|value| value.to_str())
                                .unwrap_or("task")
                        )
                    ),
                    prompt,
                    "allow",
                    format!("mt-agentrisk:benign:{tool_name}"),
                    defaults,
                    serde_json::json!({
                        "mt_agentrisk_tool": tool_name,
                        "mt_agentrisk_variant": "benign",
                        "mt_agentrisk_turn_count": 1,
                    }),
                ));
            }
        }
    }

    if cases.is_empty() {
        return Err(LogicPearlError::message(format!(
            "MT-AgentRisk dataset contains no task prompts at {}",
            dataset_root.display()
        )));
    }

    cases.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(cases)
}

pub(super) fn is_mt_agentrisk_root(path: &Path) -> bool {
    path.is_dir()
        && path.join("single_dataset.csv").is_file()
        && path.join("multi_dataset.csv").is_file()
        && path.join("workspaces").is_dir()
}

fn sorted_child_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn read_trimmed_text(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(LogicPearlError::message(format!(
            "task prompt file is empty: {}",
            path.display()
        )));
    }
    Ok(trimmed.to_string())
}

fn load_mt_agentrisk_turns(turns_path: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(turns_path)?;
    let turns_dir = turns_path.parent().unwrap_or(Path::new("."));
    if let Ok(spec) = serde_yaml::from_str::<MtAgentRiskTurnsFile>(&raw) {
        if !spec.turns.is_empty() {
            return spec
                .turns
                .iter()
                .map(|turn| read_trimmed_text(&turns_dir.join(&turn.instruction_file)))
                .collect();
        }
    }

    let mut turn_paths = fs::read_dir(turns_dir)?
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .map(|name| {
                    name.starts_with("task-turn-")
                        && path
                            .extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| ext.eq_ignore_ascii_case("md"))
                            .unwrap_or(false)
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    turn_paths.sort();
    if turn_paths.is_empty() {
        return Err(LogicPearlError::message(format!(
            "MT-AgentRisk task directory contains no task-turn markdown files: {}",
            turns_dir.display()
        )));
    }
    turn_paths
        .iter()
        .map(|path| read_trimmed_text(path))
        .collect()
}

fn render_mt_agentrisk_multi_turn_prompt(turns: &[String]) -> String {
    turns
        .iter()
        .enumerate()
        .map(|(index, turn)| format!("[Turn {}]\n{}", index + 1, turn))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn build_mt_agentrisk_case(
    id: String,
    prompt: String,
    expected_route: &str,
    category: String,
    defaults: &BenchmarkAdaptDefaults,
    extra_input: Value,
) -> BenchmarkCase {
    let mut input = serde_json::Map::new();
    input.insert("prompt".to_string(), Value::String(prompt));
    input.insert(
        "requested_tool".to_string(),
        Value::String(defaults.requested_tool.clone()),
    );
    input.insert(
        "requested_action".to_string(),
        Value::String(defaults.requested_action.clone()),
    );
    input.insert("scope".to_string(), Value::String(defaults.scope.clone()));
    if let Value::Object(fields) = extra_input {
        for (key, value) in fields {
            input.insert(key, value);
        }
    }
    BenchmarkCase {
        id,
        input: Value::Object(input),
        expected_route: expected_route.to_string(),
        category: Some(category),
    }
}
