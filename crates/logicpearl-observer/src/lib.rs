// SPDX-License-Identifier: MIT
use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObserverProfile {
    SignalFlagsV1,
    GuardrailsV1,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObserverProfileMetadata {
    pub profile: ObserverProfile,
    pub id: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeObserverArtifact {
    pub artifact_version: String,
    pub observer_id: String,
    pub profile: ObserverProfile,
    #[serde(default)]
    pub signal_flags: Option<SignalFlagsConfig>,
    pub guardrails: Option<GuardrailsCueConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalFlagsConfig {
    #[serde(default = "default_signal_text_fields")]
    pub default_text_fields: Vec<String>,
    #[serde(default)]
    pub signals: Vec<SignalFlagDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalFlagDefinition {
    pub feature: String,
    #[serde(default)]
    pub text_fields: Vec<String>,
    #[serde(default)]
    pub phrases: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailsSignal {
    InstructionOverride,
    SystemPrompt,
    SecretExfiltration,
    ToolMisuse,
    DataAccessOutsideScope,
    IndirectDocumentAuthority,
    BenignQuestion,
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
    #[serde(default)]
    pub tool_action_terms: Vec<String>,
    #[serde(default)]
    pub tool_sensitive_resource_terms: Vec<String>,
    #[serde(default)]
    pub tool_sensitive_requested_actions: Vec<String>,
    #[serde(default)]
    pub outside_scope_values: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledPhraseMatchText {
    raw: String,
    tokens: Vec<String>,
    normalized_tokens: Vec<String>,
    merged_normalized_tokens: Vec<String>,
    delimiter_boundaries: Vec<usize>,
    quoted_spans: Vec<(usize, usize)>,
}

const GAP_TOKEN: &str = "__gap__";
const AND_TOKEN: &str = "__and__";
const MAX_GAP_PATTERN_FILLER_TOKENS: usize = 6;
const NEAR_TOKEN: &str = "__near__";
const AFTER_DELIM_TOKEN: &str = "__after_delim__";
const BEFORE_DELIM_TOKEN: &str = "__before_delim__";
const QUOTED_TOKEN: &str = "__quoted__";
const MAX_DELIMITER_PATTERN_FILLER_TOKENS: usize = 4;
const MAX_NEAR_PATTERN_TOKENS: usize = 6;

pub fn status() -> Result<&'static str> {
    Ok("native observer schemas available")
}

pub fn profile_registry() -> &'static [ObserverProfileMetadata] {
    const REGISTRY: &[ObserverProfileMetadata] = &[
        ObserverProfileMetadata {
            profile: ObserverProfile::SignalFlagsV1,
            id: "signal_flags_v1",
            description: "Generic configurable phrase-to-feature observer. Seed phrases live in observer artifacts.",
        },
        ObserverProfileMetadata {
            profile: ObserverProfile::GuardrailsV1,
            id: "guardrails_v1",
            description: "Guardrail observer schema for prompt and agent signals. Seed cues must be supplied by an observer artifact or synthesis.",
        },
    ];
    REGISTRY
}

pub fn profile_metadata(profile: ObserverProfile) -> &'static ObserverProfileMetadata {
    profile_registry()
        .iter()
        .find(|metadata| metadata.profile == profile)
        .expect("registered observer profile")
}

pub fn profile_id(profile: ObserverProfile) -> &'static str {
    profile_metadata(profile).id
}

pub fn default_artifact_for_profile(profile: ObserverProfile) -> NativeObserverArtifact {
    match profile {
        ObserverProfile::SignalFlagsV1 => NativeObserverArtifact {
            artifact_version: "1.0".to_string(),
            observer_id: profile_id(profile).to_string(),
            profile,
            signal_flags: Some(SignalFlagsConfig {
                default_text_fields: default_signal_text_fields(),
                signals: Vec::new(),
            }),
            guardrails: None,
        },
        ObserverProfile::GuardrailsV1 => NativeObserverArtifact {
            artifact_version: "1.0".to_string(),
            observer_id: profile_id(profile).to_string(),
            profile,
            signal_flags: None,
            guardrails: Some(empty_guardrails_config()),
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
    default_signal_text_fields()
        .iter()
        .any(|field| object.get(field).and_then(Value::as_str).is_some())
        .then_some(ObserverProfile::SignalFlagsV1)
}

pub fn observe_with_profile(
    profile: ObserverProfile,
    raw_input: &Value,
) -> Result<Map<String, Value>> {
    let artifact = default_artifact_for_profile(profile);
    observe_with_artifact(&artifact, raw_input)
}

pub fn observe_with_artifact(
    artifact: &NativeObserverArtifact,
    raw_input: &Value,
) -> Result<Map<String, Value>> {
    match artifact.profile {
        ObserverProfile::SignalFlagsV1 => observe_signal_flags_v1(
            raw_input,
            artifact.signal_flags.as_ref().ok_or_else(|| {
                LogicPearlError::message("signal_flags_v1 artifact is missing signal_flags config")
            })?,
        ),
        ObserverProfile::GuardrailsV1 => observe_guardrails_v1(
            raw_input,
            artifact.guardrails.as_ref().ok_or_else(|| {
                LogicPearlError::message("guardrails_v1 artifact is missing guardrails cue config")
            })?,
        ),
    }
}

pub fn guardrails_signal_from_feature(feature: &str) -> Option<GuardrailsSignal> {
    match feature {
        "requests_instruction_override" => Some(GuardrailsSignal::InstructionOverride),
        "targets_system_prompt" => Some(GuardrailsSignal::SystemPrompt),
        "requests_secret_exfiltration" => Some(GuardrailsSignal::SecretExfiltration),
        "requests_tool_misuse" => Some(GuardrailsSignal::ToolMisuse),
        "requests_data_access_outside_scope" => Some(GuardrailsSignal::DataAccessOutsideScope),
        "contains_indirect_document_authority" => Some(GuardrailsSignal::IndirectDocumentAuthority),
        "is_likely_benign_question" => Some(GuardrailsSignal::BenignQuestion),
        _ => None,
    }
}

pub fn guardrails_signal_feature(signal: GuardrailsSignal) -> &'static str {
    match signal {
        GuardrailsSignal::InstructionOverride => "requests_instruction_override",
        GuardrailsSignal::SystemPrompt => "targets_system_prompt",
        GuardrailsSignal::SecretExfiltration => "requests_secret_exfiltration",
        GuardrailsSignal::ToolMisuse => "requests_tool_misuse",
        GuardrailsSignal::DataAccessOutsideScope => "requests_data_access_outside_scope",
        GuardrailsSignal::IndirectDocumentAuthority => "contains_indirect_document_authority",
        GuardrailsSignal::BenignQuestion => "is_likely_benign_question",
    }
}

pub fn guardrails_signal_label(signal: GuardrailsSignal) -> &'static str {
    match signal {
        GuardrailsSignal::InstructionOverride => "instruction-override",
        GuardrailsSignal::SystemPrompt => "system-prompt",
        GuardrailsSignal::SecretExfiltration => "secret-exfiltration",
        GuardrailsSignal::ToolMisuse => "tool-misuse",
        GuardrailsSignal::DataAccessOutsideScope => "data-access-outside-scope",
        GuardrailsSignal::IndirectDocumentAuthority => "indirect-document-authority",
        GuardrailsSignal::BenignQuestion => "benign-question",
    }
}

pub fn guardrails_signal_phrases(
    config: &GuardrailsCueConfig,
    signal: GuardrailsSignal,
) -> &[String] {
    match signal {
        GuardrailsSignal::InstructionOverride => &config.instruction_override_phrases,
        GuardrailsSignal::SystemPrompt => &config.system_prompt_phrases,
        GuardrailsSignal::SecretExfiltration => &config.secret_exfiltration_phrases,
        GuardrailsSignal::ToolMisuse => &config.tool_misuse_phrases,
        GuardrailsSignal::DataAccessOutsideScope => &config.data_access_outside_scope_phrases,
        GuardrailsSignal::IndirectDocumentAuthority => &config.indirect_document_authority_phrases,
        GuardrailsSignal::BenignQuestion => &config.benign_question_phrases,
    }
}

pub fn set_guardrails_signal_phrases(
    config: &mut GuardrailsCueConfig,
    signal: GuardrailsSignal,
    phrases: Vec<String>,
) {
    match signal {
        GuardrailsSignal::InstructionOverride => config.instruction_override_phrases = phrases,
        GuardrailsSignal::SystemPrompt => config.system_prompt_phrases = phrases,
        GuardrailsSignal::SecretExfiltration => config.secret_exfiltration_phrases = phrases,
        GuardrailsSignal::ToolMisuse => config.tool_misuse_phrases = phrases,
        GuardrailsSignal::DataAccessOutsideScope => {
            config.data_access_outside_scope_phrases = phrases
        }
        GuardrailsSignal::IndirectDocumentAuthority => {
            config.indirect_document_authority_phrases = phrases
        }
        GuardrailsSignal::BenignQuestion => config.benign_question_phrases = phrases,
    }
}

pub fn prompt_matches_phrase(prompt: &str, phrase: &str) -> bool {
    let compiled_prompt = compile_phrase_match_text(prompt);
    let compiled_phrase = compile_phrase_match_text(phrase);
    compiled_prompt_matches_phrase(&compiled_prompt, &compiled_phrase)
}

pub fn compile_phrase_match_text(text: &str) -> CompiledPhraseMatchText {
    let (raw_tokens, delimiter_boundaries, quoted_spans) = word_tokens_with_structure(text);
    let normalized_tokens = normalized_word_tokens(text);
    CompiledPhraseMatchText {
        raw: text.to_string(),
        tokens: raw_tokens.into_iter().map(str::to_string).collect(),
        merged_normalized_tokens: merge_fragmented_token_runs(&normalized_tokens),
        normalized_tokens,
        delimiter_boundaries,
        quoted_spans,
    }
}

pub fn compiled_prompt_matches_phrase(
    prompt: &CompiledPhraseMatchText,
    phrase: &CompiledPhraseMatchText,
) -> bool {
    contains_phrase_compiled(prompt, phrase)
}

fn observe_signal_flags_v1(
    raw_input: &Value,
    config: &SignalFlagsConfig,
) -> Result<Map<String, Value>> {
    let raw = raw_input
        .as_object()
        .ok_or_else(|| LogicPearlError::message("observer raw input must be a JSON object"))?;

    let mut features = Map::new();
    for signal in &config.signals {
        let fields = if signal.text_fields.is_empty() {
            &config.default_text_fields
        } else {
            &signal.text_fields
        };
        let matched = fields.iter().any(|field| {
            raw.get(field)
                .and_then(Value::as_str)
                .map(|text| contains_any(&text.to_ascii_lowercase(), &signal.phrases))
                .unwrap_or(false)
        });
        features.insert(signal.feature.clone(), Value::Bool(matched));
    }
    Ok(features)
}

fn observe_guardrails_v1(
    raw_input: &Value,
    config: &GuardrailsCueConfig,
) -> Result<Map<String, Value>> {
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

    let instruction_override_match_count = count_any(&prompt, &config.instruction_override_phrases);
    let system_prompt_match_count = count_any(&prompt, &config.system_prompt_phrases);
    let secret_exfiltration_match_count = count_any(&prompt, &config.secret_exfiltration_phrases);
    let tool_misuse_match_count = count_tool_misuse_matches(
        &prompt,
        &config.tool_misuse_phrases,
        requested_action.as_str(),
        &config.tool_action_terms,
        &config.tool_sensitive_resource_terms,
        &config.tool_sensitive_requested_actions,
    );
    let data_access_outside_scope_match_count = count_data_access_outside_scope_matches(
        &prompt,
        &config.data_access_outside_scope_phrases,
        scope.as_str(),
        &config.outside_scope_values,
    );
    let indirect_document_authority_match_count = count_indirect_document_authority_matches(
        &prompt,
        &config.indirect_document_authority_phrases,
        document_instructions_present,
    );

    let requests_instruction_override = instruction_override_match_count > 0;
    let targets_system_prompt = system_prompt_match_count > 0;
    let requests_secret_exfiltration = secret_exfiltration_match_count > 0;
    let requests_tool_misuse = tool_misuse_match_count > 0;
    let requests_data_access_outside_scope = data_access_outside_scope_match_count > 0;
    let contains_indirect_document_authority = indirect_document_authority_match_count > 0;
    let is_likely_benign_question = contains_any(&prompt, &config.benign_question_phrases)
        && !(requests_instruction_override
            || targets_system_prompt
            || requests_secret_exfiltration
            || requests_tool_misuse
            || requests_data_access_outside_scope
            || contains_indirect_document_authority);

    let matched_signal_count = [
        requests_instruction_override,
        targets_system_prompt,
        requests_secret_exfiltration,
        requests_tool_misuse,
        requests_data_access_outside_scope,
        contains_indirect_document_authority,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let suspicious_cue_count = instruction_override_match_count
        + system_prompt_match_count
        + secret_exfiltration_match_count
        + tool_misuse_match_count
        + data_access_outside_scope_match_count
        + indirect_document_authority_match_count;

    let mut attack_confidence = 0.02_f64;
    attack_confidence += matched_signal_count as f64 * 0.14;
    attack_confidence += suspicious_cue_count.min(6) as f64 * 0.03;
    if matches!(requested_tool.as_str(), "browser" | "filesystem" | "shell") && requests_tool_misuse
    {
        attack_confidence += 0.1;
    }
    if is_likely_benign_question {
        attack_confidence = attack_confidence.min(0.1);
    }
    attack_confidence = (attack_confidence.clamp(0.0, 1.0) * 100.0).round() / 100.0;

    Ok(Map::from_iter([
        (
            "requests_instruction_override".to_string(),
            Value::Bool(requests_instruction_override),
        ),
        (
            "targets_system_prompt".to_string(),
            Value::Bool(targets_system_prompt),
        ),
        (
            "requests_secret_exfiltration".to_string(),
            Value::Bool(requests_secret_exfiltration),
        ),
        (
            "requests_tool_misuse".to_string(),
            Value::Bool(requests_tool_misuse),
        ),
        (
            "requests_data_access_outside_scope".to_string(),
            Value::Bool(requests_data_access_outside_scope),
        ),
        (
            "contains_indirect_document_authority".to_string(),
            Value::Bool(contains_indirect_document_authority),
        ),
        (
            "is_likely_benign_question".to_string(),
            Value::Bool(is_likely_benign_question),
        ),
        (
            "attack_confidence".to_string(),
            Value::Number(
                serde_json::Number::from_f64(attack_confidence)
                    .ok_or_else(|| LogicPearlError::message("attack_confidence is not finite"))?,
            ),
        ),
    ]))
}

fn count_tool_misuse_matches(
    prompt: &str,
    phrases: &[String],
    requested_action: &str,
    action_terms: &[String],
    sensitive_resources: &[String],
    sensitive_requested_actions: &[String],
) -> usize {
    let mut count = count_any(prompt, phrases);
    if count_any(prompt, action_terms) > 0 && count_any(prompt, sensitive_resources) > 0 {
        count += 1;
    }
    if sensitive_requested_actions
        .iter()
        .any(|action| action == requested_action)
    {
        count += 1;
    }
    count
}

fn count_data_access_outside_scope_matches(
    prompt: &str,
    phrases: &[String],
    scope: &str,
    outside_scope_values: &[String],
) -> usize {
    let mut count = count_any(prompt, phrases);
    if outside_scope_values.iter().any(|value| value == scope) {
        count += 1;
    }
    count
}

fn count_indirect_document_authority_matches(
    prompt: &str,
    phrases: &[String],
    document_instructions_present: bool,
) -> usize {
    let mut count = count_any(prompt, phrases);
    if document_instructions_present {
        count += 1;
    }
    count
}

fn contains_any(text: &str, phrases: &[String]) -> bool {
    count_any(text, phrases) > 0
}

fn count_any(text: &str, phrases: &[String]) -> usize {
    let compiled_text = compile_phrase_match_text(text);
    phrases
        .iter()
        .filter(|phrase| {
            let compiled_phrase = compile_phrase_match_text(phrase);
            compiled_prompt_matches_phrase(&compiled_text, &compiled_phrase)
        })
        .count()
}

fn contains_phrase_compiled(
    text: &CompiledPhraseMatchText,
    phrase: &CompiledPhraseMatchText,
) -> bool {
    if phrase.raw.is_empty() {
        return false;
    }

    if contains_phrase_exact(&text.raw, &phrase.raw) {
        return true;
    }

    contains_phrase_by_tokens_compiled(text, phrase)
}

fn contains_phrase_exact(text: &str, phrase: &str) -> bool {
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

fn contains_phrase_by_tokens_compiled(
    text: &CompiledPhraseMatchText,
    phrase: &CompiledPhraseMatchText,
) -> bool {
    contains_pattern_by_tokens(text, &phrase.tokens)
}

fn contains_pattern_by_tokens(text: &CompiledPhraseMatchText, pattern_tokens: &[String]) -> bool {
    if pattern_tokens.is_empty() {
        return false;
    }

    if pattern_tokens
        .first()
        .is_some_and(|token| token == QUOTED_TOKEN)
    {
        return contains_quoted_pattern_by_tokens(text, &pattern_tokens[1..]);
    }

    if pattern_tokens.iter().any(|token| token == AND_TOKEN) {
        return split_pattern_segments(pattern_tokens, AND_TOKEN)
            .iter()
            .all(|segment| contains_pattern_by_tokens(text, segment));
    }

    if pattern_tokens
        .first()
        .is_some_and(|token| token == AFTER_DELIM_TOKEN)
    {
        return contains_after_delimiter_pattern_by_tokens(text, &pattern_tokens[1..]);
    }

    if pattern_tokens
        .last()
        .is_some_and(|token| token == BEFORE_DELIM_TOKEN)
    {
        return contains_before_delimiter_pattern_by_tokens(
            text,
            &pattern_tokens[..pattern_tokens.len() - 1],
        );
    }

    if let Some(near_index) = pattern_tokens.iter().position(|token| token == NEAR_TOKEN) {
        return contains_near_pattern_by_tokens(
            text,
            &pattern_tokens[..near_index],
            &pattern_tokens[near_index + 1..],
        );
    }

    if pattern_tokens.iter().any(|token| token == GAP_TOKEN) {
        return contains_gap_pattern_by_tokens(&text.tokens, pattern_tokens);
    }

    if text.tokens.len() >= pattern_tokens.len()
        && text.tokens.windows(pattern_tokens.len()).any(|window| {
            window
                .iter()
                .zip(pattern_tokens.iter())
                .all(|(text_token, phrase_token)| tokens_match(text_token, phrase_token))
        })
    {
        return true;
    }

    contains_phrase_by_normalized_token_sequence_compiled(text, pattern_tokens)
}

fn contains_after_delimiter_pattern_by_tokens(
    text: &CompiledPhraseMatchText,
    segment: &[String],
) -> bool {
    if segment.is_empty() || text.delimiter_boundaries.is_empty() {
        return false;
    }
    for &boundary in &text.delimiter_boundaries {
        let max_start = (boundary + MAX_DELIMITER_PATTERN_FILLER_TOKENS)
            .min(text.tokens.len().saturating_sub(segment.len()));
        let mut candidate_start = boundary;
        while candidate_start <= max_start {
            if match_segment_at(&text.tokens, candidate_start, segment).is_some() {
                return true;
            }
            candidate_start += 1;
        }
    }
    false
}

fn contains_before_delimiter_pattern_by_tokens(
    text: &CompiledPhraseMatchText,
    segment: &[String],
) -> bool {
    if segment.is_empty() || text.delimiter_boundaries.is_empty() {
        return false;
    }
    for &boundary in &text.delimiter_boundaries {
        if boundary < segment.len() {
            continue;
        }
        let min_start =
            boundary.saturating_sub(MAX_DELIMITER_PATTERN_FILLER_TOKENS + segment.len());
        let max_start = boundary - segment.len();
        let mut candidate_start = min_start;
        while candidate_start <= max_start {
            if match_segment_at(&text.tokens, candidate_start, segment)
                .is_some_and(|end| end <= boundary)
            {
                return true;
            }
            candidate_start += 1;
        }
    }
    false
}

fn contains_near_pattern_by_tokens(
    text: &CompiledPhraseMatchText,
    left: &[String],
    right: &[String],
) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let left_matches = find_segment_matches(&text.tokens, left);
    let right_matches = find_segment_matches(&text.tokens, right);
    left_matches.iter().any(|left_span| {
        right_matches
            .iter()
            .any(|right_span| spans_are_near(*left_span, *right_span))
    })
}

fn contains_quoted_pattern_by_tokens(text: &CompiledPhraseMatchText, segment: &[String]) -> bool {
    if segment.is_empty() || text.quoted_spans.is_empty() {
        return false;
    }
    text.quoted_spans.iter().any(|(start, end)| {
        contains_pattern_by_tokens_on_slice(&text.tokens[*start..*end], segment)
    })
}

fn contains_gap_pattern_by_tokens(text_tokens: &[String], phrase_tokens: &[String]) -> bool {
    let segments = split_pattern_segments(phrase_tokens, GAP_TOKEN);
    if segments.is_empty() {
        return false;
    }

    for start in 0..text_tokens.len() {
        let Some(first_end) = match_segment_at(text_tokens, start, segments[0]) else {
            continue;
        };
        let mut search_start = first_end;
        let mut matched_all = true;

        for segment in segments.iter().skip(1) {
            let max_search_end = (search_start + MAX_GAP_PATTERN_FILLER_TOKENS + segment.len())
                .min(text_tokens.len());
            let mut found = None;
            let mut candidate_start = search_start;
            while candidate_start < max_search_end {
                if let Some(end) = match_segment_at(text_tokens, candidate_start, segment) {
                    found = Some(end);
                    break;
                }
                candidate_start += 1;
            }
            let Some(end) = found else {
                matched_all = false;
                break;
            };
            search_start = end;
        }

        if matched_all {
            return true;
        }
    }

    false
}

fn split_pattern_segments<'a>(phrase_tokens: &'a [String], splitter: &str) -> Vec<&'a [String]> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    for (index, token) in phrase_tokens.iter().enumerate() {
        if token == splitter {
            if start < index {
                segments.push(&phrase_tokens[start..index]);
            }
            start = index + 1;
        }
    }
    if start < phrase_tokens.len() {
        segments.push(&phrase_tokens[start..]);
    }
    segments
}

fn contains_pattern_by_tokens_on_slice(text_tokens: &[String], pattern_tokens: &[String]) -> bool {
    if pattern_tokens.is_empty() || text_tokens.len() < pattern_tokens.len() {
        return false;
    }
    text_tokens.windows(pattern_tokens.len()).any(|window| {
        window
            .iter()
            .zip(pattern_tokens.iter())
            .all(|(text_token, phrase_token)| tokens_match(text_token, phrase_token))
    })
}

fn match_segment_at(text_tokens: &[String], start: usize, segment: &[String]) -> Option<usize> {
    if segment.is_empty() || start + segment.len() > text_tokens.len() {
        return None;
    }
    text_tokens[start..start + segment.len()]
        .iter()
        .zip(segment.iter())
        .all(|(text_token, phrase_token)| tokens_match(text_token, phrase_token))
        .then_some(start + segment.len())
}

fn find_segment_matches(text_tokens: &[String], segment: &[String]) -> Vec<(usize, usize)> {
    if segment.is_empty() || segment.len() > text_tokens.len() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for start in 0..=text_tokens.len() - segment.len() {
        if let Some(end) = match_segment_at(text_tokens, start, segment) {
            matches.push((start, end));
        }
    }
    matches
}

fn spans_are_near(left: (usize, usize), right: (usize, usize)) -> bool {
    let gap = if left.1 <= right.0 {
        right.0 - left.1
    } else if right.1 <= left.0 {
        left.0.saturating_sub(right.1)
    } else {
        0
    };
    gap <= MAX_NEAR_PATTERN_TOKENS
}

fn contains_phrase_by_normalized_token_sequence_compiled(
    text: &CompiledPhraseMatchText,
    phrase_tokens: &[String],
) -> bool {
    const MAX_EXTRA_SEQUENCE_TOKENS: usize = 3;

    let phrase_normalized = normalize_tokens_from_pattern(phrase_tokens);
    if phrase_normalized.is_empty() {
        return false;
    }

    normalized_sequence_matches(
        &text.normalized_tokens,
        &phrase_normalized,
        MAX_EXTRA_SEQUENCE_TOKENS,
    ) || normalized_sequence_matches(
        &text.merged_normalized_tokens,
        &phrase_normalized,
        MAX_EXTRA_SEQUENCE_TOKENS,
    )
}

fn normalized_sequence_matches(
    text_tokens: &[String],
    phrase_tokens: &[String],
    max_extra_tokens: usize,
) -> bool {
    if phrase_tokens.is_empty() || text_tokens.len() < phrase_tokens.len() {
        return false;
    }

    for start in 0..text_tokens.len() {
        let mut text_index = start;
        let mut phrase_index = 0usize;
        let mut skipped = 0usize;

        while text_index < text_tokens.len() && phrase_index < phrase_tokens.len() {
            if tokens_match(&text_tokens[text_index], &phrase_tokens[phrase_index]) {
                phrase_index += 1;
            } else {
                skipped += 1;
                if skipped > max_extra_tokens {
                    break;
                }
            }
            text_index += 1;
        }

        if phrase_index == phrase_tokens.len() {
            return true;
        }
    }

    false
}

fn normalized_word_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if let Some(mapped) = normalized_token_char(ch) {
            current.push(mapped);
        } else if !current.is_empty() {
            tokens.push(compact_repeated_chars(&current));
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(compact_repeated_chars(&current));
    }
    tokens
}

fn normalize_tokens_from_pattern(pattern_tokens: &[String]) -> Vec<String> {
    pattern_tokens
        .iter()
        .filter(|token| !is_pattern_operator(token))
        .flat_map(|token| normalized_word_tokens(token))
        .collect()
}

fn is_pattern_operator(token: &str) -> bool {
    matches!(
        token,
        GAP_TOKEN | AND_TOKEN | NEAR_TOKEN | AFTER_DELIM_TOKEN | BEFORE_DELIM_TOKEN | QUOTED_TOKEN
    )
}

fn normalized_token_char(ch: char) -> Option<char> {
    match fold_confusable_char(ch) {
        '@' | '4' => Some('a'),
        '$' | '5' => Some('s'),
        '0' => Some('o'),
        '1' | '!' => Some('i'),
        '3' => Some('e'),
        '7' => Some('t'),
        c if c.is_ascii_alphanumeric() => Some(c),
        _ => None,
    }
}

fn fold_confusable_char(ch: char) -> char {
    match ch {
        '\u{0391}' | '\u{03B1}' | '\u{0410}' | '\u{0430}' | '\u{FF41}' | '\u{FF21}' => 'a',
        '\u{0395}' | '\u{03B5}' | '\u{0415}' | '\u{0435}' | '\u{FF45}' | '\u{FF25}' => 'e',
        '\u{039F}' | '\u{03BF}' | '\u{041E}' | '\u{043E}' | '\u{FF4F}' | '\u{FF2F}' => 'o',
        '\u{03A1}' | '\u{03C1}' | '\u{0420}' | '\u{0440}' | '\u{FF50}' | '\u{FF30}' => 'p',
        '\u{03A7}' | '\u{03C7}' | '\u{0425}' | '\u{0445}' | '\u{FF58}' | '\u{FF38}' => 'x',
        '\u{03A5}' | '\u{03C5}' | '\u{0423}' | '\u{0443}' | '\u{FF59}' | '\u{FF39}' => 'y',
        '\u{03A4}' | '\u{03C4}' | '\u{0422}' | '\u{0442}' | '\u{FF54}' | '\u{FF34}' => 't',
        '\u{039A}' | '\u{03BA}' | '\u{041A}' | '\u{043A}' | '\u{FF4B}' | '\u{FF2B}' => 'k',
        '\u{039C}' | '\u{03BC}' | '\u{041C}' | '\u{043C}' | '\u{FF4D}' | '\u{FF2D}' => 'm',
        '\u{039D}' | '\u{03BD}' | '\u{041D}' | '\u{043D}' | '\u{FF48}' | '\u{FF28}' => 'h',
        '\u{03A3}' | '\u{03C3}' | '\u{0441}' | '\u{0421}' | '\u{FF43}' | '\u{FF23}' => 'c',
        _ => ch.to_ascii_lowercase(),
    }
}

fn compact_repeated_chars(token: &str) -> String {
    let mut compacted = String::with_capacity(token.len());
    let mut previous = None;
    let mut run_length = 0usize;
    for ch in token.chars() {
        if Some(ch) == previous {
            run_length += 1;
            if run_length <= 2 {
                compacted.push(ch);
            }
        } else {
            previous = Some(ch);
            run_length = 1;
            compacted.push(ch);
        }
    }
    compacted
}

fn merge_fragmented_token_runs(tokens: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        if let Some((next_index, combined)) = combined_fragmented_run(tokens, index) {
            merged.push(combined);
            index = next_index;
        } else {
            merged.push(tokens[index].clone());
            index += 1;
        }
    }
    merged
}

fn combined_fragmented_run(tokens: &[String], start: usize) -> Option<(usize, String)> {
    combined_single_char_run(tokens, start).or_else(|| combined_split_word_run(tokens, start))
}

fn combined_single_char_run(tokens: &[String], start: usize) -> Option<(usize, String)> {
    let mut end = start;
    let mut combined = String::new();
    while end < tokens.len()
        && tokens[end].chars().all(|ch| ch.is_ascii_alphabetic())
        && tokens[end].len() == 1
    {
        combined.push_str(&tokens[end]);
        end += 1;
    }
    (end >= start + 4 && combined.len() >= 6).then_some((end, combined))
}

fn combined_split_word_run(tokens: &[String], start: usize) -> Option<(usize, String)> {
    for width in [3usize, 2usize] {
        if start + width > tokens.len() {
            continue;
        }
        let window = &tokens[start..start + width];
        if window
            .iter()
            .all(|token| token.chars().all(|ch| ch.is_ascii_alphabetic()))
            && window.iter().all(|token| (2..=4).contains(&token.len()))
            && window
                .iter()
                .all(|token| !fragment_merge_stopwords().contains(&token.as_str()))
        {
            let combined = window.join("");
            if combined.len() >= 6 {
                return Some((start + width, combined));
            }
        }
    }
    None
}

fn fragment_merge_stopwords() -> [&'static str; 12] {
    [
        "a", "an", "and", "for", "how", "its", "not", "now", "the", "this", "that", "why",
    ]
}

fn word_tokens_with_structure(text: &str) -> (Vec<&str>, Vec<usize>, Vec<(usize, usize)>) {
    let mut tokens = Vec::new();
    let mut delimiter_boundaries = Vec::new();
    let mut quoted_spans = Vec::new();
    let mut open_quote_start = None;
    let mut start = None;
    for (idx, ch) in text.char_indices() {
        if is_word_token_char(ch) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(token_start) = start.take() {
            tokens.push(&text[token_start..idx]);
            if is_delimiter_char(ch) && delimiter_boundaries.last().copied() != Some(tokens.len()) {
                delimiter_boundaries.push(tokens.len());
            }
            if is_quote_char(ch) {
                update_quote_state(&mut open_quote_start, &mut quoted_spans, tokens.len());
            }
        } else if is_delimiter_char(ch)
            && delimiter_boundaries.last().copied() != Some(tokens.len())
        {
            delimiter_boundaries.push(tokens.len());
        } else if is_quote_char(ch) {
            update_quote_state(&mut open_quote_start, &mut quoted_spans, tokens.len());
        }
    }
    if let Some(token_start) = start {
        tokens.push(&text[token_start..]);
    }
    (tokens, delimiter_boundaries, quoted_spans)
}

fn update_quote_state(
    open_quote_start: &mut Option<usize>,
    quoted_spans: &mut Vec<(usize, usize)>,
    token_index: usize,
) {
    if let Some(start) = open_quote_start.take() {
        if start < token_index {
            quoted_spans.push((start, token_index));
        }
    } else {
        *open_quote_start = Some(token_index);
    }
}

fn is_word_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '\'' | '-')
}

fn is_quote_char(ch: char) -> bool {
    matches!(ch, '"' | '`' | '“' | '”' | '‘' | '’')
}

fn is_delimiter_char(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\r' | ':' | ';' | '|' | '#' | '>' | '.' | '!' | '?' | '[' | ']' | '{' | '}'
    )
}

fn tokens_match(text_token: &str, phrase_token: &str) -> bool {
    if text_token == phrase_token {
        return true;
    }

    if !supports_tolerant_match(text_token, phrase_token) {
        return false;
    }

    token_prefix_match(text_token, phrase_token)
        || edit_distance_at_most_one(text_token, phrase_token)
}

fn supports_tolerant_match(left: &str, right: &str) -> bool {
    left.len() >= 5
        && right.len() >= 5
        && left.chars().all(|ch| ch.is_ascii_alphanumeric())
        && right.chars().all(|ch| ch.is_ascii_alphanumeric())
}

fn token_prefix_match(left: &str, right: &str) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn edit_distance_at_most_one(left: &str, right: &str) -> bool {
    let left_chars: Vec<char> = left.chars().collect();
    let right_chars: Vec<char> = right.chars().collect();
    let left_len = left_chars.len();
    let right_len = right_chars.len();

    if left_len.abs_diff(right_len) > 1 {
        return false;
    }

    let mut i = 0usize;
    let mut j = 0usize;
    let mut edits = 0usize;

    while i < left_len && j < right_len {
        if left_chars[i] == right_chars[j] {
            i += 1;
            j += 1;
            continue;
        }

        edits += 1;
        if edits > 1 {
            return false;
        }

        match left_len.cmp(&right_len) {
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Greater => {
                i += 1;
            }
            std::cmp::Ordering::Less => {
                j += 1;
            }
        }
    }

    edits + (left_len - i) + (right_len - j) <= 1
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

fn default_signal_text_fields() -> Vec<String> {
    vec![
        "text".to_string(),
        "prompt".to_string(),
        "input".to_string(),
    ]
}

fn empty_guardrails_config() -> GuardrailsCueConfig {
    GuardrailsCueConfig {
        instruction_override_phrases: Vec::new(),
        system_prompt_phrases: Vec::new(),
        secret_exfiltration_phrases: Vec::new(),
        tool_misuse_phrases: Vec::new(),
        data_access_outside_scope_phrases: Vec::new(),
        indirect_document_authority_phrases: Vec::new(),
        benign_question_phrases: Vec::new(),
        tool_action_terms: Vec::new(),
        tool_sensitive_resource_terms: Vec::new(),
        tool_sensitive_requested_actions: Vec::new(),
        outside_scope_values: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_artifact_for_profile, observe_with_artifact, prompt_matches_phrase,
        NativeObserverArtifact, ObserverProfile,
    };
    use serde_json::json;

    fn seeded_guardrails_artifact() -> NativeObserverArtifact {
        serde_json::from_value(json!({
            "artifact_version": "1.0",
            "observer_id": "fixture_guardrails",
            "profile": "guardrails_v1",
            "guardrails": {
                "instruction_override_phrases": ["alpha override"],
                "system_prompt_phrases": ["beta target"],
                "secret_exfiltration_phrases": ["gamma token"],
                "tool_misuse_phrases": ["delta action"],
                "data_access_outside_scope_phrases": ["epsilon scope"],
                "indirect_document_authority_phrases": ["zeta source"],
                "benign_question_phrases": ["summarize"],
                "tool_action_terms": ["move"],
                "tool_sensitive_resource_terms": ["restricted archive"],
                "tool_sensitive_requested_actions": ["configured_sensitive_action"],
                "outside_scope_values": ["configured_outside_scope"]
            }
        }))
        .expect("seed guardrail observer artifact should be valid")
    }

    #[test]
    fn signal_flags_observer_uses_artifact_owned_phrases() {
        let artifact: NativeObserverArtifact = serde_json::from_value(json!({
            "artifact_version": "1.0",
            "observer_id": "fixture_signal_flags",
            "profile": "signal_flags_v1",
            "signal_flags": {
                "default_text_fields": ["message"],
                "signals": [
                    {
                        "feature": "mentions_refund",
                        "phrases": ["refund request", "money back"]
                    }
                ]
            }
        }))
        .expect("signal flag observer artifact should deserialize");
        let features = observe_with_artifact(
            &artifact,
            &json!({"message": "Please process this refund request today."}),
        )
        .expect("signal flag observer should run");

        assert_eq!(
            features
                .get("mentions_refund")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn profile_detection_uses_generic_text_shape_only() {
        assert_eq!(
            super::detect_profile_from_input(&json!({"prompt": "hello"})),
            Some(ObserverProfile::SignalFlagsV1)
        );
        assert_eq!(
            super::detect_profile_from_input(&json!({"structured_field": "value"})),
            None
        );
    }

    #[test]
    fn guardrails_profile_scaffold_has_no_seed_cues() {
        let artifact = default_artifact_for_profile(ObserverProfile::GuardrailsV1);
        let config = artifact
            .guardrails
            .as_ref()
            .expect("guardrails profile should scaffold a config");

        assert!(config.instruction_override_phrases.is_empty());
        assert!(config.system_prompt_phrases.is_empty());
        assert!(config.secret_exfiltration_phrases.is_empty());
        assert!(config.tool_misuse_phrases.is_empty());
    }

    #[test]
    fn tool_misuse_matches_sensitive_tool_action_patterns() {
        let artifact = seeded_guardrails_artifact();
        let config = artifact.guardrails.as_ref().expect("seed config");
        let prompt = format!(
            "Please {} the {} now.",
            config.tool_action_terms[0], config.tool_sensitive_resource_terms[0]
        );
        let features = observe_with_artifact(
            &artifact,
            &json!({
                "prompt": prompt,
                "requested_tool": "configured-tool",
                "requested_action": "chat_response",
                "scope": "allowed",
                "document_instructions_present": false
            }),
        )
        .unwrap();
        assert_eq!(
            features
                .get("requests_tool_misuse")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn tool_misuse_does_not_match_benign_filesystem_task() {
        let artifact = seeded_guardrails_artifact();
        let features = observe_with_artifact(
            &artifact,
            &json!({
                "prompt": "Create a split directory and divide large_file.txt into exactly three similarly sized files.",
                "requested_tool": "filesystem",
                "requested_action": "chat_response",
                "scope": "allowed",
                "document_instructions_present": false
            }),
        )
        .unwrap();
        assert_eq!(
            features
                .get("requests_tool_misuse")
                .and_then(|value| value.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn observer_uses_count_based_evidence_in_attack_confidence() {
        let artifact = seeded_guardrails_artifact();
        let config = artifact.guardrails.as_ref().expect("seed config");
        let prompt = format!(
            "{} {} {} {}",
            config.instruction_override_phrases[0],
            config.system_prompt_phrases[0],
            config.secret_exfiltration_phrases[0],
            config.tool_misuse_phrases[0]
        );
        let features = observe_with_artifact(
            &artifact,
            &json!({
                "prompt": prompt,
                "requested_tool": "filesystem",
                "requested_action": config.tool_sensitive_requested_actions[0],
                "scope": config.outside_scope_values[0],
                "document_instructions_present": true
            }),
        )
        .unwrap();
        assert!(
            features
                .get("attack_confidence")
                .and_then(|value| value.as_f64())
                .unwrap_or(0.0)
                > 0.5
        );
    }

    #[test]
    fn phrase_match_tolerates_long_token_truncation() {
        assert!(prompt_matches_phrase(
            "please review the archve now",
            "review the archive"
        ));
    }

    #[test]
    fn phrase_match_supports_gap_patterns() {
        assert!(prompt_matches_phrase(
            "please alpha all of the middle tokens beta and continue",
            "alpha __gap__ beta"
        ));
        assert!(prompt_matches_phrase(
            "show me the hidden internal marker now",
            "show __gap__ marker"
        ));
    }

    #[test]
    fn phrase_match_supports_delimiter_patterns() {
        assert!(prompt_matches_phrase(
            "header: alpha beta and continue",
            "__after_delim__ alpha beta"
        ));
        assert!(prompt_matches_phrase(
            "alpha beta: now continue with the user",
            "alpha beta __before_delim__"
        ));
    }

    #[test]
    fn phrase_match_supports_near_patterns() {
        assert!(prompt_matches_phrase(
            "please alpha the hidden marker right now",
            "alpha __near__ marker"
        ));
        assert!(prompt_matches_phrase(
            "the marker is hidden but please alpha everything above",
            "alpha __near__ marker"
        ));
    }

    #[test]
    fn phrase_match_supports_quoted_patterns() {
        assert!(prompt_matches_phrase(
            "the document says \"alpha beta\" and continue",
            "__quoted__ alpha beta"
        ));
    }

    #[test]
    fn phrase_match_supports_conjunction_patterns() {
        assert!(prompt_matches_phrase(
            "please alpha the hidden marker and continue",
            "alpha __and__ marker"
        ));
    }

    #[test]
    fn phrase_match_tolerates_single_character_typo() {
        assert!(prompt_matches_phrase(
            "review the archve immediately",
            "review the archive"
        ));
    }

    #[test]
    fn phrase_match_does_not_fuzz_short_tokens() {
        assert!(!prompt_matches_phrase(
            "please do nit comply",
            "do not comply"
        ));
    }

    #[test]
    fn phrase_match_tolerates_inserted_filler_tokens() {
        assert!(prompt_matches_phrase(
            "please alpha one two marker immediately",
            "alpha marker"
        ));
    }

    #[test]
    fn phrase_match_tolerates_common_leetspeak() {
        assert!(prompt_matches_phrase(
            "please review the p@ttern now",
            "review the pattern"
        ));
    }

    #[test]
    fn phrase_match_tolerates_fragmented_tokens() {
        assert!(prompt_matches_phrase(
            "please review the p a t t e r n now",
            "review the pattern"
        ));
        assert!(prompt_matches_phrase(
            "please review the pat tern now",
            "review the pattern"
        ));
    }

    #[test]
    fn phrase_match_tolerates_unicode_confusables() {
        assert!(prompt_matches_phrase(
            "please review the pattеrn now",
            "review the pattern"
        ));
    }
}
