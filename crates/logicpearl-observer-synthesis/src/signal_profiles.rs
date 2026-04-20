// SPDX-License-Identifier: MIT
use logicpearl_observer::GuardrailsSignal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CueVocabulary {
    pub action_tokens: Vec<String>,
    pub target_tokens: Vec<String>,
    pub tool_tokens: Vec<String>,
    pub scope_tokens: Vec<String>,
    pub source_tokens: Vec<String>,
    pub direct_tokens: Vec<String>,
}

impl CueVocabulary {
    pub fn empty() -> Self {
        Self::default()
    }

    fn from_static(definition: CueVocabularyDefinition) -> Self {
        Self {
            action_tokens: tokens(definition.action_tokens),
            target_tokens: tokens(definition.target_tokens),
            tool_tokens: tokens(definition.tool_tokens),
            scope_tokens: tokens(definition.scope_tokens),
            source_tokens: tokens(definition.source_tokens),
            direct_tokens: tokens(definition.direct_tokens),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalProfileEntry {
    pub signal: GuardrailsSignal,
    pub vocabulary: CueVocabulary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalProfile {
    pub name: String,
    pub signals: Vec<SignalProfileEntry>,
}

impl SignalProfile {
    pub fn cue_vocabulary(&self, signal: GuardrailsSignal) -> Option<&CueVocabulary> {
        self.signals
            .iter()
            .find_map(|entry| (entry.signal == signal).then_some(&entry.vocabulary))
    }

    pub fn signal_entry(&self, signal: GuardrailsSignal) -> Option<&SignalProfileEntry> {
        self.signals.iter().find(|entry| entry.signal == signal)
    }

    pub fn contains_signal(&self, signal: GuardrailsSignal) -> bool {
        self.signal_entry(signal).is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignalProfileDefinition {
    name: &'static str,
    signals: &'static [SignalProfileEntryDefinition],
}

impl SignalProfileDefinition {
    fn to_profile(self) -> SignalProfile {
        SignalProfile {
            name: self.name.to_string(),
            signals: self
                .signals
                .iter()
                .copied()
                .map(SignalProfileEntryDefinition::to_profile_entry)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignalProfileEntryDefinition {
    signal: GuardrailsSignal,
    vocabulary: CueVocabularyDefinition,
}

impl SignalProfileEntryDefinition {
    fn to_profile_entry(self) -> SignalProfileEntry {
        SignalProfileEntry {
            signal: self.signal,
            vocabulary: CueVocabulary::from_static(self.vocabulary),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CueVocabularyDefinition {
    action_tokens: &'static [&'static str],
    target_tokens: &'static [&'static str],
    tool_tokens: &'static [&'static str],
    scope_tokens: &'static [&'static str],
    source_tokens: &'static [&'static str],
    direct_tokens: &'static [&'static str],
}

impl CueVocabularyDefinition {
    const fn empty() -> Self {
        Self {
            action_tokens: &[],
            target_tokens: &[],
            tool_tokens: &[],
            scope_tokens: &[],
            source_tokens: &[],
            direct_tokens: &[],
        }
    }
}

const BUILT_IN_GUARDRAILS_PROFILE: SignalProfileDefinition = SignalProfileDefinition {
    name: "guardrails_v1",
    signals: &BUILT_IN_GUARDRAILS_SIGNALS,
};

const BUILT_IN_GUARDRAILS_SIGNALS: [SignalProfileEntryDefinition; 7] = [
    SignalProfileEntryDefinition {
        signal: GuardrailsSignal::InstructionOverride,
        vocabulary: CueVocabularyDefinition {
            action_tokens: &INSTRUCTION_OVERRIDE_VERBS,
            target_tokens: &INSTRUCTION_OVERRIDE_TARGETS,
            ..CueVocabularyDefinition::empty()
        },
    },
    SignalProfileEntryDefinition {
        signal: GuardrailsSignal::SystemPrompt,
        vocabulary: CueVocabularyDefinition {
            action_tokens: &SYSTEM_PROMPT_REQUEST_VERBS,
            target_tokens: &SYSTEM_PROMPT_TARGETS,
            ..CueVocabularyDefinition::empty()
        },
    },
    SignalProfileEntryDefinition {
        signal: GuardrailsSignal::SecretExfiltration,
        vocabulary: CueVocabularyDefinition {
            direct_tokens: &SECRET_EXFILTRATION_TOKENS,
            ..CueVocabularyDefinition::empty()
        },
    },
    SignalProfileEntryDefinition {
        signal: GuardrailsSignal::ToolMisuse,
        vocabulary: CueVocabularyDefinition {
            action_tokens: &TOOL_MISUSE_VERBS,
            target_tokens: &TOOL_MISUSE_TARGETS,
            tool_tokens: &TOOL_MISUSE_TOOL_TOKENS,
            ..CueVocabularyDefinition::empty()
        },
    },
    SignalProfileEntryDefinition {
        signal: GuardrailsSignal::DataAccessOutsideScope,
        vocabulary: CueVocabularyDefinition {
            scope_tokens: &DATA_ACCESS_SCOPE_TOKENS,
            target_tokens: &DATA_ACCESS_TARGET_TOKENS,
            ..CueVocabularyDefinition::empty()
        },
    },
    SignalProfileEntryDefinition {
        signal: GuardrailsSignal::IndirectDocumentAuthority,
        vocabulary: CueVocabularyDefinition {
            source_tokens: &INDIRECT_AUTHORITY_SOURCES,
            action_tokens: &INDIRECT_AUTHORITY_VERBS,
            ..CueVocabularyDefinition::empty()
        },
    },
    SignalProfileEntryDefinition {
        signal: GuardrailsSignal::BenignQuestion,
        vocabulary: CueVocabularyDefinition {
            direct_tokens: &BENIGN_QUESTION_TOKENS,
            ..CueVocabularyDefinition::empty()
        },
    },
];

pub fn default_guardrail_signal_profile() -> SignalProfile {
    BUILT_IN_GUARDRAILS_PROFILE.to_profile()
}

fn tokens(raw: &[&str]) -> Vec<String> {
    raw.iter().map(|token| (*token).to_string()).collect()
}

const INSTRUCTION_OVERRIDE_VERBS: [&str; 9] = [
    "ignore",
    "disregard",
    "override",
    "bypass",
    "forget",
    "drop",
    "skip",
    "shrug",
    "evade",
];

const INSTRUCTION_OVERRIDE_TARGETS: [&str; 9] = [
    "instruction",
    "instructions",
    "guideline",
    "guidelines",
    "rule",
    "rules",
    "prompt",
    "policy",
    "policies",
];

const SYSTEM_PROMPT_REQUEST_VERBS: [&str; 9] = [
    "reveal", "show", "print", "display", "dump", "expose", "quote", "repeat", "share",
];

const SYSTEM_PROMPT_TARGETS: [&str; 15] = [
    "system",
    "prompt",
    "hidden",
    "internal",
    "instruction",
    "instructions",
    "policy",
    "policies",
    "message",
    "messages",
    "preamble",
    "primer",
    "setup",
    "directive",
    "directives",
];

const SECRET_EXFILTRATION_TOKENS: [&str; 15] = [
    "api",
    "access",
    "bearer",
    "credential",
    "credentials",
    "key",
    "keys",
    "password",
    "passwords",
    "secret",
    "secrets",
    "shared",
    "token",
    "tokens",
    "vault",
];

const TOOL_MISUSE_VERBS: [&str; 16] = [
    "copy", "delete", "destroy", "download", "dump", "export", "extract", "move", "package",
    "prepare", "return", "send", "transfer", "upload", "wipe", "zip",
];

const TOOL_MISUSE_TARGETS: [&str; 18] = [
    "account",
    "credentials",
    "customer",
    "customers",
    "database",
    "emails",
    "file",
    "files",
    "funds",
    "records",
    "table",
    "tables",
    "vendor",
    "vendors",
    "workspace",
    "archive",
    "bundle",
    "payload",
];

const TOOL_MISUSE_TOOL_TOKENS: [&str; 5] = ["browser", "filesystem", "shell", "tool", "tools"];

const DATA_ACCESS_SCOPE_TOKENS: [&str; 6] = ["all", "entire", "outside", "scope", "every", "full"];

const DATA_ACCESS_TARGET_TOKENS: [&str; 8] = [
    "customer",
    "customers",
    "database",
    "emails",
    "files",
    "project",
    "records",
    "scope",
];

const INDIRECT_AUTHORITY_SOURCES: [&str; 8] = [
    "document",
    "documents",
    "email",
    "file",
    "page",
    "pdf",
    "webpage",
    "website",
];

const INDIRECT_AUTHORITY_VERBS: [&str; 8] = [
    "claims",
    "instructs",
    "says",
    "said",
    "shows",
    "states",
    "tells",
    "writes",
];

const BENIGN_QUESTION_TOKENS: [&str; 9] = [
    "explain",
    "help",
    "summarize",
    "summary",
    "translate",
    "understand",
    "why",
    "what",
    "how",
];

#[cfg(test)]
mod tests {
    use super::{default_guardrail_signal_profile, SignalProfile};
    use logicpearl_observer::GuardrailsSignal;

    #[test]
    fn built_in_guardrails_profile_round_trips_as_data() {
        let profile = default_guardrail_signal_profile();

        let encoded = serde_json::to_string(&profile).expect("profile should serialize as data");
        let decoded: SignalProfile =
            serde_json::from_str(&encoded).expect("profile data should deserialize");

        assert_eq!(decoded, profile);
        assert!(decoded.contains_signal(GuardrailsSignal::InstructionOverride));
        assert!(decoded
            .cue_vocabulary(GuardrailsSignal::InstructionOverride)
            .is_some_and(|vocabulary| vocabulary
                .action_tokens
                .iter()
                .any(|token| token == "ignore")));
    }
}
