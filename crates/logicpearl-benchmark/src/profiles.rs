// SPDX-License-Identifier: MIT
use super::{BenchmarkAdapterConfig, BenchmarkAdapterDescriptor, BenchmarkAdapterProfile};

impl BenchmarkAdapterProfile {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::CsicHttp2010 => "csic-http-2010",
            Self::ModsecurityOwasp2025 => "modsecurity-owasp-2025",
            Self::SaladBaseSet => "salad-base-set",
            Self::SaladAttackEnhancedSet => "salad-attack-enhanced-set",
            Self::SafearenaSafe => "safearena-safe",
            Self::SafearenaHarm => "safearena-harm",
            Self::Alert => "alert",
            Self::JailbreakBench => "jailbreakbench",
            Self::PromptShield => "promptshield",
            Self::RogueSecurityPromptInjections => "rogue-security-prompt-injections",
            Self::ChatgptJailbreakPrompts => "chatgpt-jailbreak-prompts",
            Self::OpenAgentSafetyS26 => "openagentsafety-s26",
            Self::McpMark => "mcpmark",
            Self::Squad => "squad",
            Self::Vigil => "vigil",
            Self::NoetiToxicQa => "noeti-toxicqa",
            Self::MtAgentRisk => "mt-agentrisk",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Auto => {
                "Detect the adapter profile from the raw dataset shape when the format is obvious."
            }
            Self::CsicHttp2010 => {
                "Adapt the CSIC 2010 HTTP request corpus into mixed allow/deny WAF benchmark cases."
            }
            Self::ModsecurityOwasp2025 => {
                "Adapt the OWASP ModSecurity 2025 audit-log corpus into mixed WAF deny/review benchmark cases."
            }
            Self::SaladBaseSet => "Adapt Salad-Data base_set rows into deny benchmark cases.",
            Self::SaladAttackEnhancedSet => {
                "Adapt Salad-Data attack_enhanced_set rows into deny benchmark cases."
            }
            Self::SafearenaSafe => "Adapt SafeArena safe task rows into allow benchmark cases.",
            Self::SafearenaHarm => "Adapt SafeArena harm task rows into deny benchmark cases.",
            Self::Alert => "Adapt ALERT adversarial instruction rows into deny benchmark cases.",
            Self::JailbreakBench => {
                "Adapt normalized JailbreakBench behavior rows into allow or deny benchmark cases."
            }
            Self::PromptShield => {
                "Adapt normalized PromptShield rows into allow or deny benchmark cases."
            }
            Self::RogueSecurityPromptInjections => {
                "Adapt normalized rogue-security prompt-injections-benchmark rows into allow or deny benchmark cases."
            }
            Self::ChatgptJailbreakPrompts => {
                "Adapt ChatGPT-Jailbreak-Prompts rows into deny benchmark cases."
            }
            Self::OpenAgentSafetyS26 => {
                "Adapt OpenAgentSafety S26 task rows into deny benchmark cases."
            }
            Self::McpMark => "Adapt MCPMark task rows into allow benchmark cases.",
            Self::Squad => "Adapt SQuAD-style benign question rows into allow benchmark cases.",
            Self::Vigil => "Adapt Vigil jailbreak scanner rows into deny benchmark cases.",
            Self::NoetiToxicQa => "Adapt NOETI ToxicQAFinal rows into deny benchmark cases.",
            Self::MtAgentRisk => {
                "Adapt the MT-AgentRisk full workspace repository into mixed allow/deny benchmark cases."
            }
        }
    }

    pub fn source_format(&self) -> &'static str {
        match self {
            Self::Auto => "Any supported raw benchmark format",
            Self::CsicHttp2010 => {
                "CSIC HTTP 2010 dataset root directory with normalTrafficTraining.txt and anomalousTrafficTest.txt"
            }
            Self::ModsecurityOwasp2025 => {
                "Extracted OWASP ModSecurity 2025 dataset root with dated modsec_audit.anon.log files"
            }
            Self::SaladBaseSet => "Salad base_set JSON array",
            Self::SaladAttackEnhancedSet => "Salad attack_enhanced_set JSON array",
            Self::SafearenaSafe => "SafeArena safe.json task array",
            Self::SafearenaHarm => "SafeArena harm.json task array",
            Self::Alert => "JSON array or JSONL of prompt-like objects",
            Self::JailbreakBench => "Normalized JailbreakBench JSON array with prompt/label rows",
            Self::PromptShield => "Normalized PromptShield JSON array with prompt/label rows",
            Self::RogueSecurityPromptInjections => {
                "Normalized rogue-security prompt-injections-benchmark JSON array with prompt/label rows"
            }
            Self::ChatgptJailbreakPrompts => "JSON array or JSONL with Prompt-style jailbreak fields",
            Self::OpenAgentSafetyS26 => "JSON array of OpenAgentSafety S26 task objects",
            Self::McpMark => "JSON array of extracted MCPMark task objects",
            Self::Squad => "SQuAD-style JSON with data[].paragraphs[].qas[]",
            Self::Vigil => "JSON array or JSONL with text, embedding, and model fields",
            Self::NoetiToxicQa => "JSON array or JSONL with prompt/topic metadata",
            Self::MtAgentRisk => "MT-AgentRisk full dataset repository directory with workspaces/",
        }
    }

    pub fn default_route(&self) -> &'static str {
        match self {
            Self::Auto => "detected",
            Self::CsicHttp2010 | Self::ModsecurityOwasp2025 => "mixed",
            Self::Squad => "allow",
            Self::SafearenaSafe | Self::McpMark => "allow",
            Self::SaladBaseSet => "deny",
            Self::SaladAttackEnhancedSet
            | Self::SafearenaHarm
            | Self::Alert
            | Self::JailbreakBench
            | Self::PromptShield
            | Self::RogueSecurityPromptInjections
            | Self::ChatgptJailbreakPrompts
            | Self::OpenAgentSafetyS26
            | Self::Vigil
            | Self::NoetiToxicQa => "deny",
            Self::MtAgentRisk => "mixed",
        }
    }
}

pub fn benchmark_adapter_registry() -> Vec<BenchmarkAdapterDescriptor> {
    [
        BenchmarkAdapterProfile::Auto,
        BenchmarkAdapterProfile::CsicHttp2010,
        BenchmarkAdapterProfile::ModsecurityOwasp2025,
        BenchmarkAdapterProfile::SaladBaseSet,
        BenchmarkAdapterProfile::SaladAttackEnhancedSet,
        BenchmarkAdapterProfile::SafearenaSafe,
        BenchmarkAdapterProfile::SafearenaHarm,
        BenchmarkAdapterProfile::Alert,
        BenchmarkAdapterProfile::JailbreakBench,
        BenchmarkAdapterProfile::PromptShield,
        BenchmarkAdapterProfile::RogueSecurityPromptInjections,
        BenchmarkAdapterProfile::ChatgptJailbreakPrompts,
        BenchmarkAdapterProfile::OpenAgentSafetyS26,
        BenchmarkAdapterProfile::McpMark,
        BenchmarkAdapterProfile::Squad,
        BenchmarkAdapterProfile::Vigil,
        BenchmarkAdapterProfile::NoetiToxicQa,
        BenchmarkAdapterProfile::MtAgentRisk,
    ]
    .into_iter()
    .map(|profile| {
        if let Some(config) = builtin_adapter_config(profile) {
            BenchmarkAdapterDescriptor {
                id: config.id,
                description: config.description,
                source_format: config.source_format,
                default_route: config.default_route,
            }
        } else {
            BenchmarkAdapterDescriptor {
                id: profile.id().to_string(),
                description: profile.description().to_string(),
                source_format: profile.source_format().to_string(),
                default_route: profile.default_route().to_string(),
            }
        }
    })
    .collect()
}

pub fn builtin_adapter_config(profile: BenchmarkAdapterProfile) -> Option<BenchmarkAdapterConfig> {
    let raw = match profile {
        BenchmarkAdapterProfile::SaladBaseSet => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/salad-base-set.yaml"
            ))
        }
        BenchmarkAdapterProfile::SaladAttackEnhancedSet => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/salad-attack-enhanced-set.yaml"
            ))
        }
        BenchmarkAdapterProfile::SafearenaSafe => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/safearena-safe.yaml"
            ))
        }
        BenchmarkAdapterProfile::SafearenaHarm => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/safearena-harm.yaml"
            ))
        }
        BenchmarkAdapterProfile::Alert => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/profiles/alert.yaml"))
        }
        BenchmarkAdapterProfile::JailbreakBench => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/jailbreakbench.yaml"
            ))
        }
        BenchmarkAdapterProfile::PromptShield => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/promptshield.yaml"
            ))
        }
        BenchmarkAdapterProfile::RogueSecurityPromptInjections => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/rogue-security-prompt-injections.yaml"
            ))
        }
        BenchmarkAdapterProfile::ChatgptJailbreakPrompts => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/chatgpt-jailbreak-prompts.yaml"
            ))
        }
        BenchmarkAdapterProfile::OpenAgentSafetyS26 => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/openagentsafety-s26.yaml"
            ))
        }
        BenchmarkAdapterProfile::McpMark => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/mcpmark.yaml"
            ))
        }
        BenchmarkAdapterProfile::Squad => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/profiles/squad.yaml"))
        }
        BenchmarkAdapterProfile::Vigil => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/profiles/vigil.yaml"))
        }
        BenchmarkAdapterProfile::NoetiToxicQa => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/profiles/noeti-toxicqa.yaml"
            ))
        }
        _ => return None,
    };
    Some(
        serde_norway::from_str(raw).expect("built-in benchmark adapter profile must be valid YAML"),
    )
}
