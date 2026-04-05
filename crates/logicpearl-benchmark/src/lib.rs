use logicpearl_core::{LogicPearlError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PintRawCase {
    pub text: String,
    #[serde(default)]
    pub category: Option<String>,
    pub label: bool,
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
    SaladBaseSet,
    SaladAttackEnhancedSet,
    Alert,
    Squad,
    Pint,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkAdapterDescriptor {
    pub id: &'static str,
    pub description: &'static str,
    pub source_format: &'static str,
    pub default_route: &'static str,
}

impl BenchmarkAdapterProfile {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::SaladBaseSet => "salad-base-set",
            Self::SaladAttackEnhancedSet => "salad-attack-enhanced-set",
            Self::Alert => "alert",
            Self::Squad => "squad",
            Self::Pint => "pint",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Auto => "Detect the adapter profile from the raw dataset shape when the format is obvious.",
            Self::SaladBaseSet => "Adapt Salad-Data benign base_set rows into allow benchmark cases.",
            Self::SaladAttackEnhancedSet => "Adapt Salad-Data attack_enhanced_set rows into deny benchmark cases.",
            Self::Alert => "Adapt ALERT adversarial instruction rows into deny benchmark cases.",
            Self::Squad => "Adapt SQuAD-style benign question rows into allow benchmark cases.",
            Self::Pint => "Adapt PINT YAML rows into allow or deny benchmark cases for proof-only scoring.",
        }
    }

    pub fn source_format(&self) -> &'static str {
        match self {
            Self::Auto => "Any supported raw benchmark format",
            Self::SaladBaseSet => "Salad base_set JSON array",
            Self::SaladAttackEnhancedSet => "Salad attack_enhanced_set JSON array",
            Self::Alert => "JSON array or JSONL of prompt-like objects",
            Self::Squad => "SQuAD-style JSON with data[].paragraphs[].qas[]",
            Self::Pint => "PINT YAML list with text/category/label",
        }
    }

    pub fn default_route(&self) -> &'static str {
        match self {
            Self::Auto => "detected",
            Self::SaladBaseSet | Self::Squad => "allow",
            Self::SaladAttackEnhancedSet | Self::Alert => "deny",
            Self::Pint => "mixed",
        }
    }
}

pub fn benchmark_adapter_registry() -> Vec<BenchmarkAdapterDescriptor> {
    [
        BenchmarkAdapterProfile::Auto,
        BenchmarkAdapterProfile::SaladBaseSet,
        BenchmarkAdapterProfile::SaladAttackEnhancedSet,
        BenchmarkAdapterProfile::Alert,
        BenchmarkAdapterProfile::Squad,
        BenchmarkAdapterProfile::Pint,
    ]
    .into_iter()
    .map(|profile| BenchmarkAdapterDescriptor {
        id: profile.id(),
        description: profile.description(),
        source_format: profile.source_format(),
        default_route: profile.default_route(),
    })
    .collect()
}

pub fn detect_benchmark_adapter_profile(path: &Path) -> Result<BenchmarkAdapterProfile> {
    let raw = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext, "yaml" | "yml"))
        .unwrap_or(false)
    {
        if let Ok(rows) = serde_yaml::from_str::<Vec<PintRawCase>>(&raw) {
            if !rows.is_empty() {
                return Ok(BenchmarkAdapterProfile::Pint);
            }
        }
    }

    if let Ok(dataset) = serde_json::from_str::<SquadDataset>(&raw) {
        if !dataset.data.is_empty() {
            return Ok(BenchmarkAdapterProfile::Squad);
        }
    }

    if let Ok(base_rows) = serde_json::from_str::<Vec<SaladBaseCase>>(&raw) {
        if !base_rows.is_empty() {
            return Ok(BenchmarkAdapterProfile::SaladBaseSet);
        }
    }

    if let Ok(attack_rows) = serde_json::from_str::<Vec<SaladAttackCase>>(&raw) {
        if !attack_rows.is_empty() {
            return Ok(BenchmarkAdapterProfile::SaladAttackEnhancedSet);
        }
    }

    if let Ok(rows) = parse_json_object_rows(&raw) {
        if !rows.is_empty() {
            let first = &rows[0];
            if first.contains_key("prompt")
                || first.contains_key("instruction")
                || first.contains_key("text")
                || first.contains_key("question")
                || first.contains_key("input")
                || first.contains_key("content")
            {
                return Ok(BenchmarkAdapterProfile::Alert);
            }
        }
    }

    Err(LogicPearlError::message(format!(
        "could not auto-detect a built-in benchmark adapter profile for {}",
        path.display()
    )))
}

pub fn load_benchmark_cases(path: &Path) -> Result<Vec<BenchmarkCase>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut cases = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: BenchmarkCase = serde_json::from_str(trimmed).map_err(|err| {
            LogicPearlError::message(format!(
                "invalid benchmark case JSON on line {}. Each line must contain id, input, and expected_route ({err})",
                line_no + 1
            ))
        })?;
        cases.push(case);
    }
    Ok(cases)
}

pub fn load_synthesis_cases(path: &Path) -> Result<Vec<SynthesisCase>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut cases = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|err| {
            LogicPearlError::message(format!("invalid JSON on line {} ({err})", line_no + 1))
        })?;
        let object = value.as_object().ok_or_else(|| {
            LogicPearlError::message(format!(
                "invalid synthesis row on line {}; each row must be a benchmark case or observed benchmark case object",
                line_no + 1
            ))
        })?;

        let prompt = object
            .get("input")
            .and_then(Value::as_object)
            .and_then(|input| input.get("prompt"))
            .and_then(Value::as_str)
            .map(|prompt| prompt.to_ascii_lowercase())
            .ok_or_else(|| {
                LogicPearlError::message(format!(
                    "synthesis row {} is missing input.prompt",
                    line_no + 1
                ))
            })?;
        let expected_route = object
            .get("expected_route")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                LogicPearlError::message(format!(
                    "synthesis row {} is missing expected_route",
                    line_no + 1
                ))
            })?;
        let features = object.get("features").and_then(Value::as_object).cloned();

        cases.push(SynthesisCase {
            prompt,
            expected_route,
            features,
        });
    }
    Ok(cases)
}

pub fn parse_json_object_rows(raw: &str) -> Result<Vec<serde_json::Map<String, Value>>> {
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) {
        let mut rows = Vec::with_capacity(items.len());
        for (index, item) in items.into_iter().enumerate() {
            let object = item.as_object().cloned().ok_or_else(|| {
                LogicPearlError::message(format!("row {} is not a JSON object", index + 1))
            })?;
            rows.push(object);
        }
        return Ok(rows);
    }

    let mut rows = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|error| {
            LogicPearlError::message(format!("invalid JSON on line {}: {}", line_no + 1, error))
        })?;
        let object = value.as_object().cloned().ok_or_else(|| {
            LogicPearlError::message(format!("line {} is not a JSON object", line_no + 1))
        })?;
        rows.push(object);
    }
    Ok(rows)
}

pub fn first_string_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

pub fn stable_value_id(value: &serde_json::Value, fallback_index: usize) -> String {
    match value {
        serde_json::Value::String(text) => sanitize_identifier(text),
        serde_json::Value::Number(number) => number.to_string(),
        _ => format!("{fallback_index:06}"),
    }
}

pub fn sanitize_identifier(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "pearl".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_benchmark_adapter_profile, BenchmarkAdapterProfile};
    use std::fs;

    #[test]
    fn detects_squad_shape() {
        let dir = tempfile::tempdir().unwrap();
        let dataset = dir.path().join("train-v2.0.json");
        fs::write(
            &dataset,
            r#"{"data":[{"title":"x","paragraphs":[{"context":"c","qas":[{"id":"q1","question":"What is this?"}]}]}]}"#,
        )
        .unwrap();
        let detected = detect_benchmark_adapter_profile(&dataset).unwrap();
        assert_eq!(detected, BenchmarkAdapterProfile::Squad);
    }
}
