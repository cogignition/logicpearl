use super::*;
use logicpearl_discovery::load_decision_traces_auto;
use logicpearl_ir::{
    validate_expression_against_schema, ComparisonValue, EvaluationConfig, Expression,
    FeatureDefinition, FeatureType, InputSchema, LogicPearlGateIr, Provenance, RuleDefinition,
    RuleKind,
};
use logicpearl_runtime::evaluate_gate;
use rand::prelude::*;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;

const TRACE_SPEC_VERSION: &str = "1.0";
const DEFAULT_TRACE_AUDIT_DRIFT_THRESHOLD: f64 = 0.15;
const DEFAULT_GENERATOR_MAX_ATTEMPT_FACTOR: usize = 20;
const NUMERIC_AUDIT_BINS: usize = 10;
const DISCRETE_AUDIT_TOP_VALUES: usize = 3;

fn trace_error(message: impl Into<String>) -> miette::Report {
    miette::miette!("{}", message.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TraceGenerationSpec {
    #[serde(default = "default_trace_spec_version")]
    trace_spec_version: String,
    #[serde(default)]
    dataset_id: Option<String>,
    #[serde(default = "default_trace_label_column")]
    label_column: String,
    row_count: usize,
    #[serde(default)]
    seed: Option<u64>,
    #[serde(default = "default_trace_minimum_class_rows")]
    minimum_allowed_rows: usize,
    #[serde(default = "default_trace_minimum_class_rows")]
    minimum_denied_rows: usize,
    #[serde(default = "default_generator_max_attempt_factor")]
    max_attempt_factor: usize,
    fields: Vec<TraceFieldSpec>,
    rules: Vec<TraceRuleSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TraceFieldRole {
    Policy,
    Nuisance,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TraceFieldSpec {
    id: String,
    #[serde(rename = "type")]
    feature_type: FeatureType,
    #[serde(default = "default_trace_field_role")]
    role: TraceFieldRole,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    values: Option<Vec<Value>>,
    #[serde(default)]
    weights: Option<Vec<f64>>,
    #[serde(default)]
    min: Option<f64>,
    #[serde(default)]
    max: Option<f64>,
    #[serde(default)]
    true_probability: Option<f64>,
    #[serde(default)]
    decimals: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TraceRuleSpec {
    id: String,
    deny_when: Expression,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Clone)]
struct GeneratedTraceRow {
    features: HashMap<String, Value>,
    allowed: bool,
}

#[derive(Debug, Clone, Copy)]
enum TraceOutputFormat {
    Csv,
    Jsonl,
    Json,
}

#[derive(Debug, Clone, Serialize)]
struct TraceGenerateReport {
    spec_path: String,
    output: String,
    format: String,
    row_count: usize,
    allowed_rows: usize,
    denied_rows: usize,
    label_column: String,
    seed: u64,
    audit: TraceAuditReport,
}

#[derive(Debug, Clone, Serialize)]
struct TraceAuditReport {
    trace_count: usize,
    label_column: String,
    allowed_rows: usize,
    denied_rows: usize,
    drift_threshold: f64,
    nuisance_field_count: usize,
    suspicious_nuisance_fields: Vec<String>,
    max_nuisance_drift: Option<f64>,
    fields: Vec<TraceFieldAudit>,
}

#[derive(Debug, Clone, Serialize)]
struct TraceFieldAudit {
    field: String,
    role: String,
    feature_type: String,
    drift_score: f64,
    suspicious: bool,
    allowed_mean: Option<f64>,
    denied_mean: Option<f64>,
    top_allowed_values: Vec<ValueShare>,
    top_denied_values: Vec<ValueShare>,
}

#[derive(Debug, Clone, Serialize)]
struct ValueShare {
    value: String,
    share: f64,
}

pub(crate) fn run_traces_generate(args: TraceGenerateArgs) -> Result<()> {
    let mut spec = load_trace_generation_spec(&args.spec)?;
    if let Some(rows) = args.rows {
        spec.row_count = rows;
    }
    if let Some(seed) = args.seed {
        spec.seed = Some(seed);
    }
    validate_trace_generation_spec(&spec)?;

    let format = resolve_trace_output_format(args.format, &args.output)?;
    let seed = spec.seed.unwrap_or(7);
    let rows = generate_trace_rows(&spec, seed)?;
    write_generated_traces(&rows, &spec, &args.output, format)?;
    let audit = audit_generated_rows(
        &rows,
        &spec.label_column,
        &field_role_map(&spec),
        &field_type_map(&spec),
        DEFAULT_TRACE_AUDIT_DRIFT_THRESHOLD,
    )?;

    let report = TraceGenerateReport {
        spec_path: args.spec.display().to_string(),
        output: args.output.display().to_string(),
        format: trace_output_format_name(format).to_string(),
        row_count: rows.len(),
        allowed_rows: rows.iter().filter(|row| row.allowed).count(),
        denied_rows: rows.iter().filter(|row| !row.allowed).count(),
        label_column: spec.label_column.clone(),
        seed,
        audit,
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Generated".bold().bright_green(),
            args.output.display()
        );
        println!("  {} {}", "Format".bright_black(), report.format);
        println!("  {} {}", "Rows".bright_black(), report.row_count);
        println!(
            "  {} {} allow / {} deny",
            "Class balance".bright_black(),
            report.allowed_rows,
            report.denied_rows
        );
        if report.audit.suspicious_nuisance_fields.is_empty() {
            println!(
                "  {} {}",
                "Nuisance audit".bright_black(),
                "clean under default drift threshold".bold()
            );
        } else {
            println!(
                "  {} {} ({})",
                "Nuisance audit".bright_black(),
                "suspicious drift detected".bright_yellow(),
                report.audit.suspicious_nuisance_fields.join(", ")
            );
        }
    }
    Ok(())
}

pub(crate) fn run_traces_audit(args: TraceAuditArgs) -> Result<()> {
    let spec = match &args.spec {
        Some(path) => Some(load_trace_generation_spec(path)?),
        None => None,
    };
    if let Some(spec) = &spec {
        validate_trace_generation_spec(spec)?;
    }
    let explicit_label = args
        .label_column
        .as_deref()
        .or_else(|| spec.as_ref().map(|spec| spec.label_column.as_str()));
    let loaded = load_decision_traces_auto(&args.traces, explicit_label, None, None)
        .into_diagnostic()
        .wrap_err("failed to load decision traces for audit")?;

    let mut roles = spec.as_ref().map(field_role_map).unwrap_or_default();
    for nuisance in &args.nuisance_fields {
        roles.insert(nuisance.clone(), TraceFieldRole::Nuisance);
    }
    let feature_types = spec.as_ref().map(field_type_map).unwrap_or_default();
    let report = audit_generated_rows(
        &loaded.rows,
        &loaded.label_column,
        &roles,
        &feature_types,
        args.drift_threshold,
    )?;

    if args.fail_on_skew && !report.suspicious_nuisance_fields.is_empty() {
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).into_diagnostic()?
            );
        }
        return Err(guidance(
            format!(
                "nuisance feature drift exceeded {:.3}: {}",
                args.drift_threshold,
                report.suspicious_nuisance_fields.join(", ")
            ),
            "Lower nuisance leakage in the generator, or raise --drift-threshold if the skew is intentional.",
        ));
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!("{}", "Trace Audit".bold().bright_blue());
        println!("  {} {}", "Rows".bright_black(), report.trace_count);
        println!(
            "  {} {} allow / {} deny",
            "Class balance".bright_black(),
            report.allowed_rows,
            report.denied_rows
        );
        println!(
            "  {} {}",
            "Label column".bright_black(),
            report.label_column
        );
        if report.suspicious_nuisance_fields.is_empty() {
            println!(
                "  {} {}",
                "Nuisance drift".bright_black(),
                "no suspicious nuisance skew detected".bold().bright_green()
            );
        } else {
            println!(
                "  {} {}",
                "Nuisance drift".bright_black(),
                report.suspicious_nuisance_fields.join(", ").bright_yellow()
            );
        }
        for field in report.fields.iter().take(5) {
            if field.role == "nuisance" && field.suspicious {
                println!(
                    "  {} {} drift={:.3}",
                    "Field".bright_black(),
                    field.field,
                    field.drift_score
                );
            }
        }
    }
    Ok(())
}

fn load_trace_generation_spec(path: &Path) -> Result<TraceGenerationSpec> {
    let payload = fs::read_to_string(path).into_diagnostic()?;
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());
    let spec = match extension.as_deref() {
        Some("yaml") | Some("yml") => serde_yaml::from_str(&payload).into_diagnostic()?,
        _ => serde_json::from_str(&payload).into_diagnostic()?,
    };
    Ok(spec)
}

fn validate_trace_generation_spec(spec: &TraceGenerationSpec) -> Result<()> {
    if spec.trace_spec_version != TRACE_SPEC_VERSION {
        return Err(trace_error(format!(
            "unsupported trace_spec_version: {}",
            spec.trace_spec_version
        )));
    }
    if spec.row_count == 0 {
        return Err(trace_error("trace generator row_count must be at least 1"));
    }
    if spec.fields.is_empty() {
        return Err(trace_error("trace generator needs at least one field"));
    }
    if spec.rules.is_empty() {
        return Err(trace_error("trace generator needs at least one deny rule"));
    }
    if spec.minimum_allowed_rows + spec.minimum_denied_rows > spec.row_count {
        return Err(trace_error(
            "minimum_allowed_rows + minimum_denied_rows cannot exceed row_count",
        ));
    }
    if spec.max_attempt_factor == 0 {
        return Err(trace_error("max_attempt_factor must be at least 1"));
    }

    let mut ids = BTreeSet::new();
    for field in &spec.fields {
        validate_trace_field_spec(field)?;
        if !ids.insert(field.id.clone()) {
            return Err(trace_error(format!(
                "duplicate trace field ids: {}",
                field.id
            )));
        }
    }
    let schema = spec_input_schema(spec)?;
    for rule in &spec.rules {
        if rule.id.is_empty() {
            return Err(trace_error("trace rule id must be non-empty"));
        }
        validate_expression_against_schema(&rule.deny_when, &schema).into_diagnostic()?;
        let referenced = expression_features(&rule.deny_when);
        for feature in referenced {
            if spec
                .fields
                .iter()
                .find(|field| field.id == feature)
                .is_some_and(|field| field.role == TraceFieldRole::Nuisance)
            {
                return Err(trace_error(format!(
                    "trace rule {} references nuisance field {}; nuisance fields must not drive labels",
                    rule.id, feature
                )));
            }
        }
    }
    Ok(())
}

fn validate_trace_field_spec(field: &TraceFieldSpec) -> Result<()> {
    if field.id.is_empty() {
        return Err(trace_error("trace field id must be non-empty"));
    }
    match field.feature_type {
        FeatureType::Bool => {
            let probability = field.true_probability.unwrap_or(0.5);
            if !(0.0..=1.0).contains(&probability) {
                return Err(trace_error(format!(
                    "bool field {} true_probability must be between 0 and 1",
                    field.id
                )));
            }
        }
        FeatureType::Int => {
            let (min, max) = numeric_range(field)?;
            if min.fract() != 0.0 || max.fract() != 0.0 {
                return Err(trace_error(format!(
                    "int field {} requires integer min/max values",
                    field.id
                )));
            }
        }
        FeatureType::Float => {
            numeric_range(field)?;
        }
        FeatureType::Enum => {
            validate_value_list(field, false)?;
        }
        FeatureType::String => {
            validate_value_list(field, true)?;
        }
    }
    if let Some(weights) = &field.weights {
        if weights
            .iter()
            .any(|weight| !weight.is_finite() || *weight < 0.0)
        {
            return Err(trace_error(format!(
                "field {} weights must be finite non-negative numbers",
                field.id
            )));
        }
        if weights.iter().all(|weight| *weight == 0.0) {
            return Err(trace_error(format!(
                "field {} weights cannot all be zero",
                field.id
            )));
        }
    }
    Ok(())
}

fn validate_value_list(field: &TraceFieldSpec, require_strings: bool) -> Result<()> {
    let values = field.values.as_ref().ok_or_else(|| {
        trace_error(format!(
            "field {} requires a non-empty values list",
            field.id
        ))
    })?;
    if values.is_empty() {
        return Err(trace_error(format!(
            "field {} requires a non-empty values list",
            field.id
        )));
    }
    if require_strings && values.iter().any(|value| !value.is_string()) {
        return Err(trace_error(format!(
            "string field {} values must all be strings",
            field.id
        )));
    }
    if let Some(weights) = &field.weights {
        if weights.len() != values.len() {
            return Err(trace_error(format!(
                "field {} weights length must match values length",
                field.id
            )));
        }
    }
    Ok(())
}

fn spec_input_schema(spec: &TraceGenerationSpec) -> Result<InputSchema> {
    Ok(InputSchema {
        features: spec
            .fields
            .iter()
            .map(|field| {
                let (min, max) = match field.feature_type {
                    FeatureType::Int | FeatureType::Float => (field.min, field.max),
                    _ => (None, None),
                };
                Ok(FeatureDefinition {
                    id: field.id.clone(),
                    feature_type: field.feature_type.clone(),
                    description: field.description.clone(),
                    values: field.values.clone(),
                    min,
                    max,
                    editable: Some(true),
                    derived: None,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn generation_gate(spec: &TraceGenerationSpec) -> Result<LogicPearlGateIr> {
    let schema = spec_input_schema(spec)?;
    let rules = spec
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| RuleDefinition {
            id: rule.id.clone(),
            kind: RuleKind::Predicate,
            bit: index as u32,
            deny_when: rule.deny_when.clone(),
            label: rule.label.clone(),
            message: rule.message.clone(),
            severity: None,
            counterfactual_hint: None,
            verification_status: None,
        })
        .collect();
    let gate = LogicPearlGateIr {
        ir_version: "1.0".to_string(),
        gate_id: spec
            .dataset_id
            .clone()
            .unwrap_or_else(|| "synthetic_trace_generation".to_string()),
        gate_type: "bitmask_gate".to_string(),
        input_schema: schema,
        rules,
        evaluation: EvaluationConfig {
            combine: "bitwise_or".to_string(),
            allow_when_bitmask: 0,
        },
        verification: None,
        provenance: Some(Provenance {
            generator: Some("logicpearl traces generate".to_string()),
            generator_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            source_commit: None,
            created_at: None,
        }),
    };
    gate.validate().into_diagnostic()?;
    Ok(gate)
}

fn generate_trace_rows(spec: &TraceGenerationSpec, seed: u64) -> Result<Vec<DecisionTraceRow>> {
    let gate = generation_gate(spec)?;
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let active_fields = spec
        .fields
        .iter()
        .filter(|field| field.role != TraceFieldRole::Nuisance)
        .collect::<Vec<_>>();
    let nuisance_fields = spec
        .fields
        .iter()
        .filter(|field| field.role == TraceFieldRole::Nuisance)
        .collect::<Vec<_>>();

    let max_attempts = spec
        .row_count
        .saturating_mul(spec.max_attempt_factor)
        .max(spec.row_count);
    let mut candidates = Vec::new();
    let mut allowed_count = 0usize;
    let mut denied_count = 0usize;
    for _ in 0..max_attempts {
        let mut features = HashMap::new();
        for field in &active_fields {
            features.insert(field.id.clone(), sample_policy_value(field, &mut rng)?);
        }
        let allowed = evaluate_gate(&gate, &features).into_diagnostic()?.is_zero();
        if allowed {
            allowed_count += 1;
        } else {
            denied_count += 1;
        }
        candidates.push(GeneratedTraceRow { features, allowed });
        if candidates.len() >= spec.row_count
            && allowed_count >= spec.minimum_allowed_rows
            && denied_count >= spec.minimum_denied_rows
        {
            break;
        }
    }

    if candidates.len() < spec.row_count
        || allowed_count < spec.minimum_allowed_rows
        || denied_count < spec.minimum_denied_rows
    {
        return Err(guidance(
            format!(
                "trace generation could not satisfy the requested class balance after {} attempts",
                max_attempts
            ),
            "Relax the minimum_*_rows settings or adjust the field distributions so the deny rules fire more naturally.",
        ));
    }

    let mut selected_indexes = BTreeSet::new();
    for (required_allowed, target_allowed) in [
        (spec.minimum_allowed_rows, true),
        (spec.minimum_denied_rows, false),
    ] {
        let mut taken = 0usize;
        for (index, row) in candidates.iter().enumerate() {
            if row.allowed == target_allowed && taken < required_allowed {
                selected_indexes.insert(index);
                taken += 1;
            }
        }
    }
    for index in 0..candidates.len() {
        if selected_indexes.len() >= spec.row_count {
            break;
        }
        selected_indexes.insert(index);
    }

    let mut rows = selected_indexes
        .into_iter()
        .map(|index| candidates[index].clone())
        .collect::<Vec<_>>();
    rows.truncate(spec.row_count);

    if rows.iter().filter(|row| row.allowed).count() < spec.minimum_allowed_rows
        || rows.iter().filter(|row| !row.allowed).count() < spec.minimum_denied_rows
    {
        return Err(guidance(
            "trace generation could not assemble a final dataset with the requested class minima",
            "Adjust the field distributions or increase row_count so both allow and deny examples appear often enough.",
        ));
    }

    let allowed_indexes = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| row.allowed.then_some(index))
        .collect::<Vec<_>>();
    let denied_indexes = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (!row.allowed).then_some(index))
        .collect::<Vec<_>>();

    for field in nuisance_fields {
        let mut allow_values = generate_nuisance_values(
            field,
            allowed_indexes.len(),
            derived_seed(seed, &field.id, 1),
        )?;
        let mut deny_values = generate_nuisance_values(
            field,
            denied_indexes.len(),
            derived_seed(seed, &field.id, 2),
        )?;
        for (row_index, value) in allowed_indexes.iter().zip(allow_values.drain(..)) {
            rows[*row_index].features.insert(field.id.clone(), value);
        }
        for (row_index, value) in denied_indexes.iter().zip(deny_values.drain(..)) {
            rows[*row_index].features.insert(field.id.clone(), value);
        }
    }

    Ok(rows
        .into_iter()
        .map(|row| DecisionTraceRow {
            features: row.features,
            allowed: row.allowed,
        })
        .collect())
}

fn sample_policy_value(field: &TraceFieldSpec, rng: &mut ChaCha8Rng) -> Result<Value> {
    match field.feature_type {
        FeatureType::Bool => Ok(Value::Bool(
            rng.gen_bool(field.true_probability.unwrap_or(0.5)),
        )),
        FeatureType::Int => {
            let (min, max) = numeric_range(field)?;
            let value = rng.gen_range(min as i64..=max as i64);
            Ok(Value::Number(value.into()))
        }
        FeatureType::Float => {
            let (min, max) = numeric_range(field)?;
            let value = rng.gen_range(min..=max);
            number_value(round_float(value, field.decimals.unwrap_or(2)))
        }
        FeatureType::Enum | FeatureType::String => {
            let values = field.values.as_ref().expect("validated values");
            let index = choose_weighted_index(values.len(), field.weights.as_deref(), rng)?;
            Ok(values[index].clone())
        }
    }
}

fn generate_nuisance_values(field: &TraceFieldSpec, count: usize, seed: u64) -> Result<Vec<Value>> {
    let mut values = match field.feature_type {
        FeatureType::Bool => balanced_bool_values(field.true_probability.unwrap_or(0.5), count),
        FeatureType::Enum | FeatureType::String => balanced_discrete_values(
            field.values.as_ref().expect("validated values"),
            field.weights.as_deref(),
            count,
        )?,
        FeatureType::Int => {
            let (min, max) = numeric_range(field)?;
            balanced_numeric_values(min, max, count, true, field.decimals.unwrap_or(0))?
        }
        FeatureType::Float => {
            let (min, max) = numeric_range(field)?;
            balanced_numeric_values(min, max, count, false, field.decimals.unwrap_or(2))?
        }
    };
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    values.shuffle(&mut rng);
    Ok(values)
}

fn balanced_bool_values(true_probability: f64, count: usize) -> Vec<Value> {
    let true_count = proportional_counts(&[1.0 - true_probability, true_probability], count)
        .get(1)
        .copied()
        .unwrap_or(0);
    let mut values = Vec::with_capacity(count);
    values.extend((0..true_count).map(|_| Value::Bool(true)));
    values.extend((true_count..count).map(|_| Value::Bool(false)));
    values
}

fn balanced_discrete_values(
    values: &[Value],
    weights: Option<&[f64]>,
    count: usize,
) -> Result<Vec<Value>> {
    let counts = proportional_counts(&normalized_weights(values.len(), weights)?, count);
    let mut out = Vec::with_capacity(count);
    for (value, repeats) in values.iter().zip(counts.into_iter()) {
        for _ in 0..repeats {
            out.push(value.clone());
        }
    }
    Ok(out)
}

fn balanced_numeric_values(
    min: f64,
    max: f64,
    count: usize,
    integral: bool,
    decimals: u32,
) -> Result<Vec<Value>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if (max - min).abs() < f64::EPSILON {
        let constant = if integral {
            Value::Number((min.round() as i64).into())
        } else {
            number_value(round_float(min, decimals))?
        };
        return Ok((0..count).map(|_| constant.clone()).collect());
    }
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let quantile = (index as f64 + 0.5) / count as f64;
        let raw = min + (max - min) * quantile;
        if integral {
            out.push(Value::Number((raw.round() as i64).into()));
        } else {
            out.push(number_value(round_float(raw, decimals))?);
        }
    }
    Ok(out)
}

fn audit_generated_rows(
    rows: &[DecisionTraceRow],
    label_column: &str,
    roles: &HashMap<String, TraceFieldRole>,
    feature_types: &HashMap<String, FeatureType>,
    drift_threshold: f64,
) -> Result<TraceAuditReport> {
    if rows.is_empty() {
        return Err(trace_error("trace audit needs at least one row"));
    }
    let allowed_rows = rows.iter().filter(|row| row.allowed).count();
    let denied_rows = rows.len() - allowed_rows;
    if allowed_rows == 0 || denied_rows == 0 {
        return Err(trace_error(
            "trace audit needs at least one allowed row and one denied row",
        ));
    }

    let mut field_names = BTreeSet::new();
    for row in rows {
        field_names.extend(row.features.keys().cloned());
    }

    let mut fields = Vec::new();
    for field in field_names {
        let allowed_values = rows
            .iter()
            .filter(|row| row.allowed)
            .filter_map(|row| row.features.get(&field))
            .collect::<Vec<_>>();
        let denied_values = rows
            .iter()
            .filter(|row| !row.allowed)
            .filter_map(|row| row.features.get(&field))
            .collect::<Vec<_>>();
        if allowed_values.is_empty() || denied_values.is_empty() {
            continue;
        }
        let feature_type = feature_types
            .get(&field)
            .cloned()
            .unwrap_or_else(|| infer_feature_type(allowed_values[0]));
        let role = roles
            .get(&field)
            .cloned()
            .unwrap_or(TraceFieldRole::Unknown);
        let audit = match feature_type {
            FeatureType::Int | FeatureType::Float => audit_numeric_field(
                &field,
                role,
                &feature_type,
                &allowed_values,
                &denied_values,
                drift_threshold,
            )?,
            _ => audit_discrete_field(
                &field,
                role,
                &feature_type,
                &allowed_values,
                &denied_values,
                drift_threshold,
            )?,
        };
        fields.push(audit);
    }

    fields.sort_by(|left, right| {
        right
            .drift_score
            .partial_cmp(&left.drift_score)
            .unwrap_or(Ordering::Equal)
    });

    let suspicious_nuisance_fields = fields
        .iter()
        .filter(|field| field.role == "nuisance" && field.suspicious)
        .map(|field| field.field.clone())
        .collect::<Vec<_>>();
    let max_nuisance_drift = fields
        .iter()
        .filter(|field| field.role == "nuisance")
        .map(|field| field.drift_score)
        .max_by(|left, right| left.partial_cmp(right).unwrap_or(Ordering::Equal));

    Ok(TraceAuditReport {
        trace_count: rows.len(),
        label_column: label_column.to_string(),
        allowed_rows,
        denied_rows,
        drift_threshold,
        nuisance_field_count: fields
            .iter()
            .filter(|field| field.role == "nuisance")
            .count(),
        suspicious_nuisance_fields,
        max_nuisance_drift,
        fields,
    })
}

fn audit_numeric_field(
    field: &str,
    role: TraceFieldRole,
    feature_type: &FeatureType,
    allowed_values: &[&Value],
    denied_values: &[&Value],
    drift_threshold: f64,
) -> Result<TraceFieldAudit> {
    let allowed = allowed_values
        .iter()
        .map(|value| {
            value
                .as_f64()
                .ok_or_else(|| trace_error(format!("field {field} contains a non-numeric value")))
        })
        .collect::<Result<Vec<_>>>()?;
    let denied = denied_values
        .iter()
        .map(|value| {
            value
                .as_f64()
                .ok_or_else(|| trace_error(format!("field {field} contains a non-numeric value")))
        })
        .collect::<Result<Vec<_>>>()?;
    let min = allowed
        .iter()
        .chain(denied.iter())
        .fold(f64::INFINITY, |acc, value| acc.min(*value));
    let max = allowed
        .iter()
        .chain(denied.iter())
        .fold(f64::NEG_INFINITY, |acc, value| acc.max(*value));
    let drift_score = histogram_total_variation(&allowed, &denied, min, max);
    let suspicious = role == TraceFieldRole::Nuisance && drift_score > drift_threshold;
    Ok(TraceFieldAudit {
        field: field.to_string(),
        role: trace_field_role_name(&role).to_string(),
        feature_type: trace_feature_type_name(feature_type).to_string(),
        drift_score,
        suspicious,
        allowed_mean: Some(allowed.iter().sum::<f64>() / allowed.len() as f64),
        denied_mean: Some(denied.iter().sum::<f64>() / denied.len() as f64),
        top_allowed_values: Vec::new(),
        top_denied_values: Vec::new(),
    })
}

fn audit_discrete_field(
    field: &str,
    role: TraceFieldRole,
    feature_type: &FeatureType,
    allowed_values: &[&Value],
    denied_values: &[&Value],
    drift_threshold: f64,
) -> Result<TraceFieldAudit> {
    let allowed = value_share_map(allowed_values)?;
    let denied = value_share_map(denied_values)?;
    let mut all_keys = BTreeSet::new();
    all_keys.extend(allowed.keys().cloned());
    all_keys.extend(denied.keys().cloned());
    let drift_score = 0.5
        * all_keys
            .iter()
            .map(|key| {
                (allowed.get(key).copied().unwrap_or(0.0) - denied.get(key).copied().unwrap_or(0.0))
                    .abs()
            })
            .sum::<f64>();
    let suspicious = role == TraceFieldRole::Nuisance && drift_score > drift_threshold;
    Ok(TraceFieldAudit {
        field: field.to_string(),
        role: trace_field_role_name(&role).to_string(),
        feature_type: trace_feature_type_name(feature_type).to_string(),
        drift_score,
        suspicious,
        allowed_mean: None,
        denied_mean: None,
        top_allowed_values: top_value_shares(&allowed),
        top_denied_values: top_value_shares(&denied),
    })
}

fn value_share_map(values: &[&Value]) -> Result<BTreeMap<String, f64>> {
    let mut counts = BTreeMap::new();
    for value in values {
        let key = serde_json::to_string(value).into_diagnostic()?;
        *counts.entry(key).or_insert(0usize) += 1;
    }
    Ok(counts
        .into_iter()
        .map(|(value, count)| (value, count as f64 / values.len() as f64))
        .collect())
}

fn top_value_shares(values: &BTreeMap<String, f64>) -> Vec<ValueShare> {
    let mut shares = values
        .iter()
        .map(|(value, share)| ValueShare {
            value: value.clone(),
            share: *share,
        })
        .collect::<Vec<_>>();
    shares.sort_by(|left, right| {
        right
            .share
            .partial_cmp(&left.share)
            .unwrap_or(Ordering::Equal)
    });
    shares.truncate(DISCRETE_AUDIT_TOP_VALUES);
    shares
}

fn histogram_total_variation(allowed: &[f64], denied: &[f64], min: f64, max: f64) -> f64 {
    if allowed.is_empty() || denied.is_empty() || !min.is_finite() || !max.is_finite() {
        return 0.0;
    }
    if (max - min).abs() < f64::EPSILON {
        return 0.0;
    }
    let mut allowed_bins = [0usize; NUMERIC_AUDIT_BINS];
    let mut denied_bins = [0usize; NUMERIC_AUDIT_BINS];
    for value in allowed {
        allowed_bins[histogram_bin(*value, min, max)] += 1;
    }
    for value in denied {
        denied_bins[histogram_bin(*value, min, max)] += 1;
    }
    0.5 * allowed_bins
        .iter()
        .zip(denied_bins.iter())
        .map(|(left, right)| {
            (*left as f64 / allowed.len() as f64 - *right as f64 / denied.len() as f64).abs()
        })
        .sum::<f64>()
}

fn histogram_bin(value: f64, min: f64, max: f64) -> usize {
    let scaled = ((value - min) / (max - min)).clamp(0.0, 0.999_999);
    (scaled * NUMERIC_AUDIT_BINS as f64).floor() as usize
}

fn write_generated_traces(
    rows: &[DecisionTraceRow],
    spec: &TraceGenerationSpec,
    output: &Path,
    format: TraceOutputFormat,
) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    match format {
        TraceOutputFormat::Csv => write_generated_traces_csv(rows, spec, output),
        TraceOutputFormat::Jsonl => write_generated_traces_jsonl(rows, spec, output),
        TraceOutputFormat::Json => write_generated_traces_json(rows, spec, output),
    }
}

fn write_generated_traces_csv(
    rows: &[DecisionTraceRow],
    spec: &TraceGenerationSpec,
    output: &Path,
) -> Result<()> {
    let mut writer = csv::Writer::from_path(output).into_diagnostic()?;
    let mut headers = spec
        .fields
        .iter()
        .map(|field| field.id.clone())
        .collect::<Vec<_>>();
    headers.push(spec.label_column.clone());
    writer.write_record(&headers).into_diagnostic()?;
    for row in rows {
        let mut record = Vec::with_capacity(headers.len());
        for field in &spec.fields {
            let value = row.features.get(&field.id).ok_or_else(|| {
                trace_error(format!("generated row is missing field {}", field.id))
            })?;
            record.push(value_to_csv_cell(value)?);
        }
        record.push(row.allowed.to_string());
        writer.write_record(&record).into_diagnostic()?;
    }
    writer.flush().into_diagnostic()?;
    Ok(())
}

fn write_generated_traces_jsonl(
    rows: &[DecisionTraceRow],
    spec: &TraceGenerationSpec,
    output: &Path,
) -> Result<()> {
    let mut payload = String::new();
    for row in rows {
        let mut object = BTreeMap::new();
        for field in &spec.fields {
            object.insert(
                field.id.clone(),
                row.features.get(&field.id).cloned().ok_or_else(|| {
                    trace_error(format!("generated row is missing field {}", field.id))
                })?,
            );
        }
        object.insert(spec.label_column.clone(), Value::Bool(row.allowed));
        payload.push_str(&serde_json::to_string(&object).into_diagnostic()?);
        payload.push('\n');
    }
    fs::write(output, payload).into_diagnostic()?;
    Ok(())
}

fn write_generated_traces_json(
    rows: &[DecisionTraceRow],
    spec: &TraceGenerationSpec,
    output: &Path,
) -> Result<()> {
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let mut object = serde_json::Map::new();
        for field in &spec.fields {
            object.insert(
                field.id.clone(),
                row.features.get(&field.id).cloned().ok_or_else(|| {
                    trace_error(format!("generated row is missing field {}", field.id))
                })?,
            );
        }
        object.insert(spec.label_column.clone(), Value::Bool(row.allowed));
        records.push(Value::Object(object));
    }
    fs::write(
        output,
        serde_json::to_string_pretty(&records).into_diagnostic()? + "\n",
    )
    .into_diagnostic()?;
    Ok(())
}

fn value_to_csv_cell(value: &Value) -> Result<String> {
    match value {
        Value::Null => Err(trace_error("generated trace values cannot be null")),
        Value::Bool(boolean) => Ok(boolean.to_string()),
        Value::Number(number) => Ok(number.to_string()),
        Value::String(string) => Ok(string.clone()),
        _ => Err(trace_error("generated trace values must be scalar")),
    }
}

fn resolve_trace_output_format(
    explicit: Option<TraceFormatArg>,
    output: &Path,
) -> Result<TraceOutputFormat> {
    if let Some(explicit) = explicit {
        return Ok(match explicit {
            TraceFormatArg::Csv => TraceOutputFormat::Csv,
            TraceFormatArg::Jsonl => TraceOutputFormat::Jsonl,
            TraceFormatArg::Json => TraceOutputFormat::Json,
        });
    }
    match output
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("csv") => Ok(TraceOutputFormat::Csv),
        Some("jsonl") | Some("ndjson") => Ok(TraceOutputFormat::Jsonl),
        Some("json") => Ok(TraceOutputFormat::Json),
        _ => Err(guidance(
            format!(
                "could not infer trace output format from {}",
                output.display()
            ),
            "Use --format csv, --format jsonl, or --format json.",
        )),
    }
}

fn normalized_weights(count: usize, weights: Option<&[f64]>) -> Result<Vec<f64>> {
    match weights {
        Some(weights) => {
            if weights.len() != count {
                return Err(trace_error("weights length must match values length"));
            }
            let total = weights.iter().sum::<f64>();
            if total <= 0.0 {
                return Err(trace_error("weights must sum to a positive value"));
            }
            Ok(weights.iter().map(|weight| weight / total).collect())
        }
        None => Ok(vec![1.0 / count as f64; count]),
    }
}

fn proportional_counts(weights: &[f64], count: usize) -> Vec<usize> {
    if count == 0 {
        return vec![0; weights.len()];
    }
    let mut entries = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| {
            let target = *weight * count as f64;
            let floor = target.floor() as usize;
            (index, floor, target - floor as f64)
        })
        .collect::<Vec<_>>();
    let mut counts = entries
        .iter()
        .map(|(_, floor, _)| *floor)
        .collect::<Vec<_>>();
    let assigned = counts.iter().sum::<usize>();
    let remaining = count.saturating_sub(assigned);
    entries.sort_by(|left, right| right.2.partial_cmp(&left.2).unwrap_or(Ordering::Equal));
    for (index, _, _) in entries.into_iter().take(remaining) {
        counts[index] += 1;
    }
    counts
}

fn choose_weighted_index(
    count: usize,
    weights: Option<&[f64]>,
    rng: &mut ChaCha8Rng,
) -> Result<usize> {
    let weights = normalized_weights(count, weights)?;
    let needle = rng.gen_range(0.0..1.0);
    let mut cumulative = 0.0;
    for (index, weight) in weights.iter().enumerate() {
        cumulative += *weight;
        if needle <= cumulative || index == count - 1 {
            return Ok(index);
        }
    }
    Ok(count.saturating_sub(1))
}

fn numeric_range(field: &TraceFieldSpec) -> Result<(f64, f64)> {
    let min = field
        .min
        .ok_or_else(|| trace_error(format!("field {} requires min", field.id)))?;
    let max = field
        .max
        .ok_or_else(|| trace_error(format!("field {} requires max", field.id)))?;
    if min > max {
        return Err(trace_error(format!(
            "field {} min cannot exceed max",
            field.id
        )));
    }
    Ok((min, max))
}

fn round_float(value: f64, decimals: u32) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (value * factor).round() / factor
}

fn number_value(value: f64) -> Result<Value> {
    Ok(Value::Number(Number::from_f64(value).ok_or_else(|| {
        trace_error("could not represent generated float value")
    })?))
}

fn expression_features(expression: &Expression) -> BTreeSet<String> {
    match expression {
        Expression::Comparison(comparison) => {
            let mut out = BTreeSet::from([comparison.feature.clone()]);
            if let ComparisonValue::FeatureRef { feature_ref } = &comparison.value {
                out.insert(feature_ref.clone());
            }
            out
        }
        Expression::All { all } => all
            .iter()
            .flat_map(expression_features)
            .collect::<BTreeSet<_>>(),
        Expression::Any { any } => any
            .iter()
            .flat_map(expression_features)
            .collect::<BTreeSet<_>>(),
        Expression::Not { expr } => expression_features(expr),
    }
}

fn field_role_map(spec: &TraceGenerationSpec) -> HashMap<String, TraceFieldRole> {
    spec.fields
        .iter()
        .map(|field| (field.id.clone(), field.role.clone()))
        .collect()
}

fn field_type_map(spec: &TraceGenerationSpec) -> HashMap<String, FeatureType> {
    spec.fields
        .iter()
        .map(|field| (field.id.clone(), field.feature_type.clone()))
        .collect()
}

fn infer_feature_type(value: &Value) -> FeatureType {
    match value {
        Value::Bool(_) => FeatureType::Bool,
        Value::Number(number) if number.is_i64() || number.is_u64() => FeatureType::Int,
        Value::Number(_) => FeatureType::Float,
        Value::String(_) => FeatureType::String,
        _ => FeatureType::String,
    }
}

fn trace_output_format_name(format: TraceOutputFormat) -> &'static str {
    match format {
        TraceOutputFormat::Csv => "csv",
        TraceOutputFormat::Jsonl => "jsonl",
        TraceOutputFormat::Json => "json",
    }
}

fn trace_feature_type_name(feature_type: &FeatureType) -> &'static str {
    match feature_type {
        FeatureType::Bool => "bool",
        FeatureType::Int => "int",
        FeatureType::Float => "float",
        FeatureType::String => "string",
        FeatureType::Enum => "enum",
    }
}

fn trace_field_role_name(role: &TraceFieldRole) -> &'static str {
    match role {
        TraceFieldRole::Policy => "policy",
        TraceFieldRole::Nuisance => "nuisance",
        TraceFieldRole::Unknown => "unknown",
    }
}

fn derived_seed(base_seed: u64, field_id: &str, discriminator: u64) -> u64 {
    let mut hasher = DefaultHasher::new();
    base_seed.hash(&mut hasher);
    field_id.hash(&mut hasher);
    discriminator.hash(&mut hasher);
    hasher.finish()
}

fn default_trace_spec_version() -> String {
    TRACE_SPEC_VERSION.to_string()
}

fn default_trace_label_column() -> String {
    "allowed".to_string()
}

fn default_trace_field_role() -> TraceFieldRole {
    TraceFieldRole::Unknown
}

fn default_trace_minimum_class_rows() -> usize {
    1
}

fn default_generator_max_attempt_factor() -> usize {
    DEFAULT_GENERATOR_MAX_ATTEMPT_FACTOR
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proportional_counts_preserve_total() {
        let counts = proportional_counts(&[0.2, 0.3, 0.5], 17);
        assert_eq!(counts.iter().sum::<usize>(), 17);
    }

    #[test]
    fn expression_feature_scan_collects_feature_refs() {
        let expression = Expression::All {
            all: vec![
                Expression::Comparison(logicpearl_ir::ComparisonExpression {
                    feature: "clearance".to_string(),
                    op: logicpearl_ir::ComparisonOperator::Lt,
                    value: ComparisonValue::FeatureRef {
                        feature_ref: "sensitivity".to_string(),
                    },
                }),
                Expression::Comparison(logicpearl_ir::ComparisonExpression {
                    feature: "role".to_string(),
                    op: logicpearl_ir::ComparisonOperator::Eq,
                    value: ComparisonValue::Literal(json!("viewer")),
                }),
            ],
        };
        let features = expression_features(&expression);
        assert!(features.contains("clearance"));
        assert!(features.contains("sensitivity"));
        assert!(features.contains("role"));
    }

    #[test]
    fn nuisance_audit_flags_heavy_discrete_drift() {
        let rows = vec![
            DecisionTraceRow {
                features: HashMap::from([("device".to_string(), json!("web"))]),
                allowed: true,
            },
            DecisionTraceRow {
                features: HashMap::from([("device".to_string(), json!("web"))]),
                allowed: true,
            },
            DecisionTraceRow {
                features: HashMap::from([("device".to_string(), json!("mobile"))]),
                allowed: false,
            },
            DecisionTraceRow {
                features: HashMap::from([("device".to_string(), json!("mobile"))]),
                allowed: false,
            },
        ];
        let report = audit_generated_rows(
            &rows,
            "allowed",
            &HashMap::from([("device".to_string(), TraceFieldRole::Nuisance)]),
            &HashMap::from([("device".to_string(), FeatureType::Enum)]),
            0.15,
        )
        .expect("audit should succeed");
        assert_eq!(
            report.suspicious_nuisance_fields,
            vec!["device".to_string()]
        );
    }
}
