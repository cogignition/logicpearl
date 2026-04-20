// SPDX-License-Identifier: MIT
use logicpearl_observer::GuardrailsSignal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CueVocabulary {
    pub action_tokens: &'static [&'static str],
    pub target_tokens: &'static [&'static str],
    pub tool_tokens: &'static [&'static str],
    pub scope_tokens: &'static [&'static str],
    pub source_tokens: &'static [&'static str],
    pub direct_tokens: &'static [&'static str],
}

impl CueVocabulary {
    pub const fn empty() -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalProfile {
    pub name: &'static str,
    pub instruction_override: CueVocabulary,
    pub system_prompt: CueVocabulary,
    pub secret_exfiltration: CueVocabulary,
    pub tool_misuse: CueVocabulary,
    pub data_access_outside_scope: CueVocabulary,
    pub indirect_document_authority: CueVocabulary,
    pub benign_question: CueVocabulary,
}

impl SignalProfile {
    pub const fn cue_vocabulary(&self, signal: GuardrailsSignal) -> CueVocabulary {
        match signal {
            GuardrailsSignal::InstructionOverride => self.instruction_override,
            GuardrailsSignal::SystemPrompt => self.system_prompt,
            GuardrailsSignal::SecretExfiltration => self.secret_exfiltration,
            GuardrailsSignal::ToolMisuse => self.tool_misuse,
            GuardrailsSignal::DataAccessOutsideScope => self.data_access_outside_scope,
            GuardrailsSignal::IndirectDocumentAuthority => self.indirect_document_authority,
            GuardrailsSignal::BenignQuestion => self.benign_question,
        }
    }
}

pub const fn default_guardrail_signal_profile() -> SignalProfile {
    SignalProfile {
        name: "guardrails_v1",
        instruction_override: CueVocabulary {
            action_tokens: instruction_override_verbs(),
            target_tokens: instruction_override_targets(),
            ..CueVocabulary::empty()
        },
        system_prompt: CueVocabulary {
            action_tokens: system_prompt_request_verbs(),
            target_tokens: system_prompt_targets(),
            ..CueVocabulary::empty()
        },
        secret_exfiltration: CueVocabulary {
            direct_tokens: secret_exfiltration_tokens(),
            ..CueVocabulary::empty()
        },
        tool_misuse: CueVocabulary {
            action_tokens: tool_misuse_verbs(),
            target_tokens: tool_misuse_targets(),
            tool_tokens: tool_misuse_tool_tokens(),
            ..CueVocabulary::empty()
        },
        data_access_outside_scope: CueVocabulary {
            scope_tokens: data_access_scope_tokens(),
            target_tokens: data_access_target_tokens(),
            ..CueVocabulary::empty()
        },
        indirect_document_authority: CueVocabulary {
            source_tokens: indirect_authority_sources(),
            action_tokens: indirect_authority_verbs(),
            ..CueVocabulary::empty()
        },
        benign_question: CueVocabulary {
            direct_tokens: benign_question_tokens(),
            ..CueVocabulary::empty()
        },
    }
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

pub(crate) const fn instruction_override_verbs() -> &'static [&'static str] {
    &INSTRUCTION_OVERRIDE_VERBS
}

pub(crate) const fn instruction_override_targets() -> &'static [&'static str] {
    &INSTRUCTION_OVERRIDE_TARGETS
}

pub(crate) const fn system_prompt_request_verbs() -> &'static [&'static str] {
    &SYSTEM_PROMPT_REQUEST_VERBS
}

pub(crate) const fn system_prompt_targets() -> &'static [&'static str] {
    &SYSTEM_PROMPT_TARGETS
}

pub(crate) const fn secret_exfiltration_tokens() -> &'static [&'static str] {
    &SECRET_EXFILTRATION_TOKENS
}

pub(crate) const fn tool_misuse_verbs() -> &'static [&'static str] {
    &TOOL_MISUSE_VERBS
}

pub(crate) const fn tool_misuse_targets() -> &'static [&'static str] {
    &TOOL_MISUSE_TARGETS
}

pub(crate) const fn tool_misuse_tool_tokens() -> &'static [&'static str] {
    &TOOL_MISUSE_TOOL_TOKENS
}

pub(crate) const fn data_access_scope_tokens() -> &'static [&'static str] {
    &DATA_ACCESS_SCOPE_TOKENS
}

pub(crate) const fn data_access_target_tokens() -> &'static [&'static str] {
    &DATA_ACCESS_TARGET_TOKENS
}

pub(crate) const fn indirect_authority_sources() -> &'static [&'static str] {
    &INDIRECT_AUTHORITY_SOURCES
}

pub(crate) const fn indirect_authority_verbs() -> &'static [&'static str] {
    &INDIRECT_AUTHORITY_VERBS
}

pub(crate) const fn benign_question_tokens() -> &'static [&'static str] {
    &BENIGN_QUESTION_TOKENS
}
