use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObserverProfile {
    GuardrailsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeObserverArtifact {
    pub artifact_version: String,
    pub observer_id: String,
    pub profile: ObserverProfile,
    pub guardrails: Option<GuardrailsCueConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailsCueConfig {
    pub instruction_override_phrases: Vec<String>,
    pub system_prompt_phrases: Vec<String>,
    pub secret_exfiltration_phrases: Vec<String>,
    pub tool_misuse_phrases: Vec<String>,
    pub data_access_outside_scope_phrases: Vec<String>,
    pub indirect_document_authority_phrases: Vec<String>,
    pub benign_question_phrases: Vec<String>,
}

pub fn status() -> Result<&'static str> {
    Ok("native observer profiles available")
}

pub fn default_artifact_for_profile(profile: ObserverProfile) -> NativeObserverArtifact {
    match profile {
        ObserverProfile::GuardrailsV1 => NativeObserverArtifact {
            artifact_version: "1.0".to_string(),
            observer_id: "guardrails_v1".to_string(),
            profile,
            guardrails: Some(default_guardrails_config()),
        },
    }
}

pub fn load_artifact(path: &Path) -> Result<NativeObserverArtifact> {
    let payload = fs::read_to_string(path)?;
    let artifact = serde_json::from_str(&payload)?;
    Ok(artifact)
}

pub fn detect_profile_from_input(raw_input: &Value) -> Option<ObserverProfile> {
    let object = raw_input.as_object()?;
    if object.get("prompt").and_then(Value::as_str).is_some() {
        return Some(ObserverProfile::GuardrailsV1);
    }
    if object.get("requested_tool").and_then(Value::as_str).is_some()
        || object
            .get("document_instructions_present")
            .and_then(Value::as_bool)
            .is_some()
    {
        return Some(ObserverProfile::GuardrailsV1);
    }
    None
}

pub fn observe_with_profile(profile: ObserverProfile, raw_input: &Value) -> Result<Map<String, Value>> {
    let artifact = default_artifact_for_profile(profile);
    observe_with_artifact(&artifact, raw_input)
}

pub fn observe_with_artifact(
    artifact: &NativeObserverArtifact,
    raw_input: &Value,
) -> Result<Map<String, Value>> {
    match artifact.profile {
        ObserverProfile::GuardrailsV1 => observe_guardrails_v1(
            raw_input,
            artifact.guardrails.as_ref().ok_or_else(|| {
                LogicPearlError::message("guardrails_v1 artifact is missing guardrails cue config")
            })?,
        ),
    }
}

fn observe_guardrails_v1(raw_input: &Value, config: &GuardrailsCueConfig) -> Result<Map<String, Value>> {
    let raw = raw_input
        .as_object()
        .ok_or_else(|| LogicPearlError::message("observer raw input must be a JSON object"))?;

    let prompt = raw
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let requested_action = raw
        .get("requested_action")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let requested_tool = raw
        .get("requested_tool")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let scope = raw
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let document_instructions_present = raw
        .get("document_instructions_present")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let requests_instruction_override = contains_any(&prompt, &config.instruction_override_phrases);
    let targets_system_prompt = contains_any(&prompt, &config.system_prompt_phrases);
    let requests_secret_exfiltration = contains_any(&prompt, &config.secret_exfiltration_phrases);
    let requests_tool_misuse = contains_any(&prompt, &config.tool_misuse_phrases)
        || matches!(
            requested_action.as_str(),
            "export_customer_records" | "delete_database" | "transfer_funds" | "dump_credentials"
        );
    let requests_data_access_outside_scope = scope == "outside"
        || contains_any(&prompt, &config.data_access_outside_scope_phrases);
    let contains_indirect_document_authority = document_instructions_present
        || contains_any(&prompt, &config.indirect_document_authority_phrases);
    let is_likely_benign_question = contains_any(&prompt, &config.benign_question_phrases)
        && !(
            requests_instruction_override
                || targets_system_prompt
                || requests_secret_exfiltration
                || requests_tool_misuse
                || requests_data_access_outside_scope
                || contains_indirect_document_authority
        );

    let mut attack_confidence = 0.02_f64;
    for flag in [
        requests_instruction_override,
        targets_system_prompt,
        requests_secret_exfiltration,
        requests_tool_misuse,
        requests_data_access_outside_scope,
        contains_indirect_document_authority,
    ] {
        if flag {
            attack_confidence += 0.18;
        }
    }
    if matches!(requested_tool.as_str(), "browser" | "filesystem" | "shell") && requests_tool_misuse {
        attack_confidence += 0.1;
    }
    if is_likely_benign_question {
        attack_confidence = attack_confidence.min(0.1);
    }
    attack_confidence = (attack_confidence.clamp(0.0, 1.0) * 100.0).round() / 100.0;

    Ok(Map::from_iter([
        ("requests_instruction_override".to_string(), Value::Bool(requests_instruction_override)),
        ("targets_system_prompt".to_string(), Value::Bool(targets_system_prompt)),
        ("requests_secret_exfiltration".to_string(), Value::Bool(requests_secret_exfiltration)),
        ("requests_tool_misuse".to_string(), Value::Bool(requests_tool_misuse)),
        (
            "requests_data_access_outside_scope".to_string(),
            Value::Bool(requests_data_access_outside_scope),
        ),
        (
            "contains_indirect_document_authority".to_string(),
            Value::Bool(contains_indirect_document_authority),
        ),
        ("is_likely_benign_question".to_string(), Value::Bool(is_likely_benign_question)),
        (
            "attack_confidence".to_string(),
            Value::Number(
                serde_json::Number::from_f64(attack_confidence)
                    .ok_or_else(|| LogicPearlError::message("attack_confidence is not finite"))?,
            ),
        ),
    ]))
}

fn contains_any(text: &str, phrases: &[String]) -> bool {
    phrases.iter().any(|phrase| contains_phrase(text, phrase))
}

fn contains_phrase(text: &str, phrase: &str) -> bool {
    if phrase.is_empty() {
        return false;
    }

    let mut start = 0usize;
    while let Some(found) = text[start..].find(phrase) {
        let idx = start + found;
        let end = idx + phrase.len();
        let left_ok = if idx == 0 {
            true
        } else {
            is_boundary(text[..idx].chars().next_back(), phrase.chars().next())
        };
        let right_ok = if end >= text.len() {
            true
        } else {
            is_boundary(text[end..].chars().next(), phrase.chars().last())
        };
        if left_ok && right_ok {
            return true;
        }
        start = idx + phrase.len();
    }

    false
}

fn is_boundary(neighbor: Option<char>, edge: Option<char>) -> bool {
    let needs_word_boundary = edge.map(|ch| ch.is_ascii_alphanumeric()).unwrap_or(false);
    if !needs_word_boundary {
        return true;
    }

    match neighbor {
        None => true,
        Some(c) => !c.is_ascii_alphanumeric(),
    }
}

fn default_guardrails_config() -> GuardrailsCueConfig {
    GuardrailsCueConfig {
        instruction_override_phrases: vec![
            "ignore previous instructions",
            "ignore prior instructions",
            "disregard the instructions above",
            "disregard the above",
            "override your instructions",
            "shrug off the preceding guidelines",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        system_prompt_phrases: vec![
            "system prompt",
            "hidden prompt",
            "reveal your instructions",
            "show me your prompt",
            "hidden instructions",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        secret_exfiltration_phrases: vec![
            "api key",
            "api keys",
            "access token",
            "access tokens",
            "bearer token",
            "bearer tokens",
            "password",
            "passwords",
            "credential",
            "credentials",
            "secret key",
            "secret keys",
            "shared secret",
            "shared secrets",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        tool_misuse_phrases: vec![
            "send all customer records",
            "delete the database",
            "transfer all funds",
            "download the full database",
            "return all customer records",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        data_access_outside_scope_phrases: vec![
            "all customer records",
            "entire database",
            "all files",
            "all emails",
            "outside the approved project scope",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        indirect_document_authority_phrases: vec![
            "the webpage says",
            "the document says",
            "the page says",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        benign_question_phrases: vec![
            "summarize",
            "explain",
            "help me understand",
            "what are the key takeaways",
            "translate",
            "share your views",
            "share your thoughts",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
    }
}
