// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub id: String,
    pub input: Value,
    pub expected_route: String,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedBenchmarkCase {
    pub id: String,
    pub input: Value,
    pub expected_route: String,
    #[serde(default)]
    pub category: Option<String>,
    pub features: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone)]
pub struct SynthesisCase {
    pub prompt: String,
    pub expected_route: String,
    pub features: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Clone)]
pub struct SynthesisCaseRow {
    pub id: String,
    pub case: SynthesisCase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaladBaseCase {
    pub qid: serde_json::Value,
    pub question: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaladAttackCase {
    pub aid: serde_json::Value,
    pub augq: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default, rename = "1-category")]
    pub category_1: Option<String>,
    #[serde(default, rename = "2-category")]
    pub category_2: Option<String>,
    #[serde(default, rename = "3-category")]
    pub category_3: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquadDataset {
    pub data: Vec<SquadArticle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquadArticle {
    #[serde(default)]
    pub title: Option<String>,
    pub paragraphs: Vec<SquadParagraph>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquadParagraph {
    pub context: String,
    pub qas: Vec<SquadQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquadQuestion {
    pub id: String,
    pub question: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkAdapterProfile {
    Auto,
    CsicHttp2010,
    ModsecurityOwasp2025,
    SaladBaseSet,
    SaladAttackEnhancedSet,
    SafearenaSafe,
    SafearenaHarm,
    Alert,
    JailbreakBench,
    PromptShield,
    RogueSecurityPromptInjections,
    ChatgptJailbreakPrompts,
    OpenAgentSafetyS26,
    McpMark,
    Squad,
    Vigil,
    NoetiToxicQa,
    MtAgentRisk,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkAdapterDescriptor {
    pub id: String,
    pub description: String,
    pub source_format: String,
    pub default_route: String,
}

#[derive(Debug, Clone)]
pub struct BenchmarkAdaptDefaults {
    pub requested_tool: String,
    pub requested_action: String,
    pub scope: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaladSubsetKind {
    BaseSet,
    AttackEnhancedSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkAdapterConfig {
    pub version: String,
    pub id: String,
    pub description: String,
    pub source_format: String,
    pub default_route: String,
    pub source: BenchmarkAdapterSourceConfig,
    pub output: BenchmarkAdapterOutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkAdapterSourceConfig {
    pub parser: BenchmarkAdapterParser,
    #[serde(default)]
    pub prompt_fields: Vec<String>,
    #[serde(default)]
    pub id_fields: Vec<String>,
    #[serde(default)]
    pub category_fields: Vec<String>,
    #[serde(default)]
    pub label_fields: Vec<String>,
    #[serde(default)]
    pub input_fields: Vec<BenchmarkAdapterInputField>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkAdapterParser {
    JsonObjectRows,
    YamlObjectRows,
    SquadQuestions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkAdapterOutputConfig {
    #[serde(default)]
    pub expected_route: Option<String>,
    pub id_prefix: String,
    #[serde(default)]
    pub static_input: BTreeMap<String, Value>,
    #[serde(default)]
    pub boolean_label_routes: Option<BooleanLabelRouteConfig>,
    #[serde(default)]
    pub default_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanLabelRouteConfig {
    pub true_route: String,
    pub false_route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkAdapterInputField {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub mode: BenchmarkAdapterInputFieldMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkAdapterInputFieldMode {
    #[default]
    Raw,
    FirstString,
}
