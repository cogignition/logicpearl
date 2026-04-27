// SPDX-License-Identifier: MIT
use logicpearl_core::{artifact_hash, Result};
use logicpearl_ir::{
    ComparisonExpression, ComparisonOperator, ComparisonValue, DerivedFeatureDefinition,
    DerivedFeatureOperator, Expression, FeatureDefinition, FeatureType, LogicPearlGateIr,
    RuleDefinition, RuleEvidence, RuleKind, RuleSupportEvidence, RuleTraceEvidence,
    RuleVerificationStatus,
};
use logicpearl_runtime::evaluate_gate;
use serde::Serialize;
use serde_json::{Number, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{
    DecisionTraceRow, ProposalCandidateReport, ProposalCandidateStatus, ProposalEvidenceReport,
    ProposalExactTraceConflictReport, ProposalPhaseReport, ProposalPhaseStatus,
    ProposalStageReport, ProposalStageStatus, ProposalValidationReport,
};

const PROPOSAL_RULE_COMPLEXITY_THRESHOLD: usize = 16;
const MAX_PROPOSAL_CANDIDATES: usize = 16;
const MAX_NUMERIC_FEATURES: usize = 8;
const MAX_THRESHOLDS_PER_FEATURE: usize = 24;

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TrainingMismatchSummary {
    pub total_mismatches: usize,
    pub missed_denies: usize,
    pub false_denies: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct TrainingEvaluation {
    pub(crate) correct: usize,
    pub(crate) mismatches: Vec<TrainingMismatch>,
}

#[derive(Debug, Clone)]
pub(crate) struct TrainingMismatch {
    pub(crate) row_index: usize,
    pub(crate) expected_allowed: bool,
    pub(crate) predicted_allowed: bool,
}

#[derive(Debug, Clone)]
struct CandidateProbe {
    proposal_id: String,
    proposal_type: String,
    source_stage: String,
    reason: String,
    recommendation: Option<String>,
    feature_expression: Option<String>,
    suggested_region: BTreeMap<String, Value>,
    predicted_allowed: Option<bool>,
    predicate: ProbePredicate,
}

#[derive(Debug, Clone)]
enum ProbePredicate {
    ScalarEq {
        feature: String,
        value: Value,
    },
    NumericRange {
        feature: String,
        min: f64,
        max: f64,
    },
    NumericThreshold {
        feature: String,
        op: ThresholdOp,
        threshold: f64,
    },
    NumericRatioThreshold {
        numerator: String,
        denominator: String,
        op: ThresholdOp,
        threshold: f64,
    },
    NumericDifferenceThreshold {
        left: String,
        right: String,
        op: ThresholdOp,
        threshold: f64,
    },
}

#[derive(Debug, Clone, Copy)]
enum ThresholdOp {
    Gte,
    Lte,
}

pub(crate) fn evaluate_training_rows(
    gate: &LogicPearlGateIr,
    rows: &[DecisionTraceRow],
) -> Result<TrainingEvaluation> {
    let mut correct = 0usize;
    let mut mismatches = Vec::new();
    for (row_index, row) in rows.iter().enumerate() {
        let bitmask = evaluate_gate(gate, &row.features)?;
        let predicted_allowed = bitmask.is_zero();
        if predicted_allowed == row.allowed {
            correct += 1;
        } else {
            mismatches.push(TrainingMismatch {
                row_index,
                expected_allowed: row.allowed,
                predicted_allowed,
            });
        }
    }
    Ok(TrainingEvaluation {
        correct,
        mismatches,
    })
}

pub(crate) fn detect_exact_trace_conflicts(
    rows: &[DecisionTraceRow],
) -> Vec<ProposalExactTraceConflictReport> {
    #[derive(Default)]
    struct ExactConflictGroup {
        row_indexes: Vec<usize>,
        label_counts: BTreeMap<String, usize>,
    }

    let mut groups = BTreeMap::<String, ExactConflictGroup>::new();
    for (row_index, row) in rows.iter().enumerate() {
        let signature = canonical_feature_signature(&row.features);
        let group = groups.entry(signature).or_default();
        group.row_indexes.push(row_index);
        *group
            .label_counts
            .entry(row.allowed.to_string())
            .or_default() += 1;
    }

    groups
        .into_iter()
        .filter(|(_signature, group)| group.label_counts.len() > 1)
        .map(|(signature, group)| ProposalExactTraceConflictReport {
            feature_hash: artifact_hash(&signature),
            row_indexes: group.row_indexes,
            label_counts: group.label_counts,
        })
        .collect()
}

pub(crate) fn build_auto_proposal_phase_report(
    rows: &[DecisionTraceRow],
    gate: &LogicPearlGateIr,
    mismatches: &[TrainingMismatch],
    exact_trace_conflicts: Vec<ProposalExactTraceConflictReport>,
) -> ProposalPhaseReport {
    let mismatch_summary = mismatch_summary(mismatches);
    if !exact_trace_conflicts.is_empty() {
        return exact_trace_conflict_report(exact_trace_conflicts);
    }

    if mismatches.is_empty() && gate.rules.len() <= PROPOSAL_RULE_COMPLEXITY_THRESHOLD {
        return ProposalPhaseReport {
            diagnosis: Some("clean_replay".to_string()),
            recommended_next_phase: Some("none".to_string()),
            reason: "training parity and rule complexity are within the automatic proposal budget"
                .to_string(),
            ..ProposalPhaseReport::default()
        };
    }

    let trigger = if mismatches.is_empty() {
        "rule_complexity_budget"
    } else {
        "training_mismatch_cluster"
    };
    let mut stages = Vec::new();
    let mut candidates = Vec::new();

    stages.push(mismatch_mining_stage(rows, mismatches, &mismatch_summary));
    if mismatches.is_empty() {
        let candidate = complexity_review_candidate(gate.rules.len(), &mismatch_summary);
        stages.push(stage_report(
            "rule_complexity",
            ProposalStageStatus::Completed,
            Some("rule count exceeded proposal threshold".to_string()),
            1,
            [("rule_count", json_number(gate.rules.len()))],
        ));
        candidates.push(candidate);
    } else {
        let subgroup = subgroup_rule_candidates(rows, mismatches, &mismatch_summary);
        stages.push(stage_report(
            "subgroup_discovery",
            ProposalStageStatus::Completed,
            Some("mined scalar and numeric regions around mismatch rows".to_string()),
            subgroup.len(),
            [],
        ));
        candidates.extend(subgroup);

        let derived = derived_feature_candidates(rows, mismatches, &mismatch_summary);
        stages.push(stage_report(
            "derived_feature_search",
            ProposalStageStatus::Completed,
            Some("tested ratio and difference thresholds over numeric feature pairs".to_string()),
            derived.len(),
            [],
        ));
        candidates.extend(derived);

        let models = interpretable_model_candidates(rows, mismatches, &mismatch_summary);
        stages.push(stage_report(
            "interpretable_model_search",
            ProposalStageStatus::Completed,
            Some("tested one-feature decision stumps over numeric features".to_string()),
            models.len(),
            [],
        ));
        candidates.extend(models);
    }

    let mut candidates = dedupe_candidates(candidates);
    candidates.sort_by(compare_candidate_reports);
    candidates.truncate(MAX_PROPOSAL_CANDIDATES);

    let validated_candidates = candidates
        .iter()
        .filter(|candidate| candidate.status == ProposalCandidateStatus::Validated)
        .count();
    let rejected_candidates = candidates
        .iter()
        .filter(|candidate| candidate.status == ProposalCandidateStatus::Rejected)
        .count();
    ProposalPhaseReport {
        status: ProposalPhaseStatus::Ran,
        trigger: Some(trigger.to_string()),
        diagnosis: Some(proposal_diagnosis(trigger, &candidates).to_string()),
        recommended_next_phase: Some(recommended_next_phase(trigger, &candidates).to_string()),
        reason: proposal_reason(trigger, mismatches.len(), gate.rules.len()),
        acceptance_policy: "report_only".to_string(),
        candidates_tested: candidates.len(),
        validated_candidates,
        accepted_candidates: 0,
        rejected_candidates,
        stages,
        candidates,
        ..ProposalPhaseReport::default()
    }
}

pub(crate) fn auto_adopt_safe_proposals(
    gate: &mut LogicPearlGateIr,
    rows: &[DecisionTraceRow],
    report: &mut ProposalPhaseReport,
) -> Result<TrainingEvaluation> {
    report.acceptance_policy = "auto_adopt_safe".to_string();
    report.residual_risk =
        Some("validated on training replay only; no holdout set was provided".to_string());

    if report.trigger.as_deref() == Some("exact_trace_conflict") {
        report.post_adoption_training_parity = report.pre_adoption_training_parity;
        return evaluate_training_rows(gate, rows);
    }

    let selected = select_auto_adopt_candidates(report);
    if selected.is_empty() {
        report.post_adoption_training_parity = report.pre_adoption_training_parity;
        return evaluate_training_rows(gate, rows);
    }

    report.accepted_because = vec![
        "no_exact_trace_conflicts".to_string(),
        "proposal_policy=auto_adopt_safe".to_string(),
        "candidate_type=derived_feature".to_string(),
        "deterministic_training_replay_passed".to_string(),
        "introduced_mismatches=0".to_string(),
        "fixed_mismatches>=2".to_string(),
        "non_id_feature".to_string(),
        "derived_feature_expression_present".to_string(),
    ];

    for proposal_id in selected {
        let Some(candidate) = report
            .candidates
            .iter()
            .find(|candidate| candidate.proposal_id == proposal_id)
            .cloned()
        else {
            continue;
        };
        let Some(rule) = adopted_rule_from_candidate(gate, rows, &candidate)? else {
            continue;
        };
        report.accepted_candidate_ids.push(candidate.proposal_id);
        gate.rules.push(rule);
    }

    gate.validate()?;
    let final_evaluation = evaluate_training_rows(gate, rows)?;
    report.accepted_candidates = report.accepted_candidate_ids.len();
    report.post_adoption_training_parity =
        Some(final_evaluation.correct as f64 / rows.len() as f64);
    Ok(final_evaluation)
}

fn select_auto_adopt_candidates(report: &ProposalPhaseReport) -> Vec<String> {
    let mut remaining_mismatches = report
        .candidates
        .iter()
        .flat_map(|candidate| candidate.evidence.covered_mismatch_rows.to_vec())
        .collect::<BTreeSet<_>>();
    if remaining_mismatches.is_empty() {
        return Vec::new();
    }

    let mut candidates = report
        .candidates
        .iter()
        .filter(|candidate| is_auto_adopt_safe_candidate(candidate))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| compare_auto_adopt_candidate(left, right));

    let mut selected = Vec::new();
    for candidate in candidates {
        let newly_fixed = candidate
            .evidence
            .covered_mismatch_rows
            .iter()
            .filter(|row_index| remaining_mismatches.contains(row_index))
            .count();
        if newly_fixed == 0 {
            continue;
        }
        selected.push(candidate.proposal_id.clone());
        for row_index in &candidate.evidence.covered_mismatch_rows {
            remaining_mismatches.remove(row_index);
        }
        if remaining_mismatches.is_empty() {
            break;
        }
    }
    selected
}

fn is_auto_adopt_safe_candidate(candidate: &ProposalCandidateReport) -> bool {
    candidate.status == ProposalCandidateStatus::Validated
        && candidate.source_stage == "derived_feature_search"
        && candidate.proposal_type == "derived_feature"
        && candidate.recommendation.as_deref() == Some("promote_to_observer_feature")
        && candidate.feature_expression.is_some()
        && candidate.validation.deterministic
        && candidate.validation.passed
        && candidate.evidence.introduced_mismatches == 0
        && candidate.evidence.fixed_mismatches >= 2
}

fn compare_auto_adopt_candidate(
    left: &ProposalCandidateReport,
    right: &ProposalCandidateReport,
) -> std::cmp::Ordering {
    right
        .evidence
        .fixed_mismatches
        .cmp(&left.evidence.fixed_mismatches)
        .then_with(|| proposal_operator_rank(right).cmp(&proposal_operator_rank(left)))
        .then_with(|| left.evidence.covered_rows.cmp(&right.evidence.covered_rows))
        .then_with(|| left.proposal_id.cmp(&right.proposal_id))
}

fn proposal_operator_rank(candidate: &ProposalCandidateReport) -> usize {
    match candidate
        .suggested_region
        .get("derived_operator")
        .and_then(Value::as_str)
    {
        Some("ratio") => 2,
        Some("difference") => 1,
        _ => 0,
    }
}

fn adopted_rule_from_candidate(
    gate: &mut LogicPearlGateIr,
    rows: &[DecisionTraceRow],
    candidate: &ProposalCandidateReport,
) -> Result<Option<RuleDefinition>> {
    let Some((feature_id, derived)) = derived_feature_from_candidate(candidate) else {
        return Ok(None);
    };
    ensure_gate_feature(
        gate,
        &feature_id,
        derived,
        candidate.feature_expression.as_deref(),
    );

    let Some(threshold) = candidate
        .suggested_region
        .get("threshold")
        .and_then(Value::as_f64)
    else {
        return Ok(None);
    };
    let Some(op) = candidate
        .suggested_region
        .get("operator")
        .and_then(Value::as_str)
        .and_then(comparison_operator_from_label)
    else {
        return Ok(None);
    };

    let bit = gate
        .rules
        .iter()
        .map(|rule| rule.bit)
        .max()
        .map(|bit| bit + 1)
        .unwrap_or(0);
    let rule_id = format!("auto_proposal_{:03}", bit);
    let expression = Expression::Comparison(ComparisonExpression {
        feature: feature_id.clone(),
        op,
        value: ComparisonValue::Literal(json_f64(threshold)),
    });
    let evidence = adopted_rule_evidence(rows, candidate);
    let label = format!(
        "{} {} {}",
        candidate
            .feature_expression
            .as_deref()
            .unwrap_or(feature_id.as_str()),
        candidate
            .suggested_region
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("matches"),
        threshold
    );
    Ok(Some(RuleDefinition {
        id: rule_id,
        kind: RuleKind::Predicate,
        bit,
        deny_when: expression,
        label: Some(label.clone()),
        message: Some(format!(
            "{label}. Auto-adopted from proposal {}.",
            candidate.proposal_id
        )),
        severity: None,
        counterfactual_hint: Some(format!("Change {}", feature_id)),
        verification_status: Some(RuleVerificationStatus::PipelineUnverified),
        evidence: Some(evidence),
    }))
}

fn exact_trace_conflict_report(
    exact_trace_conflicts: Vec<ProposalExactTraceConflictReport>,
) -> ProposalPhaseReport {
    let conflicting_rows = exact_trace_conflicts
        .iter()
        .map(|conflict| conflict.row_indexes.len())
        .sum::<usize>();
    ProposalPhaseReport {
        status: ProposalPhaseStatus::Ran,
        trigger: Some("exact_trace_conflict".to_string()),
        diagnosis: Some("exact_trace_conflict".to_string()),
        recommended_next_phase: Some("add_missing_feature_or_adjudicate_labels".to_string()),
        reason: format!(
            "found {} exact normalized feature conflict group(s); proposal search cannot infer one deterministic answer without another feature or label adjudication",
            exact_trace_conflicts.len()
        ),
        acceptance_policy: "report_only".to_string(),
        stages: vec![stage_report(
            "exact_trace_conflict_detection",
            ProposalStageStatus::Completed,
            Some("same normalized features map to multiple labels".to_string()),
            0,
            [
                ("conflict_groups", json_number(exact_trace_conflicts.len())),
                ("conflicting_rows", json_number(conflicting_rows)),
            ],
        )],
        exact_trace_conflicts,
        ..ProposalPhaseReport::default()
    }
}

fn mismatch_mining_stage(
    rows: &[DecisionTraceRow],
    mismatches: &[TrainingMismatch],
    summary: &TrainingMismatchSummary,
) -> ProposalStageReport {
    let mismatched_features = mismatches
        .iter()
        .filter_map(|mismatch| rows.get(mismatch.row_index))
        .flat_map(|row| row.features.keys().cloned())
        .collect::<BTreeSet<_>>()
        .len();
    stage_report(
        "mismatch_mining",
        ProposalStageStatus::Completed,
        Some("summarized replay mismatches before proposal search".to_string()),
        0,
        [
            ("total_mismatches", json_number(summary.total_mismatches)),
            ("missed_denies", json_number(summary.missed_denies)),
            ("false_denies", json_number(summary.false_denies)),
            ("mismatched_features", json_number(mismatched_features)),
        ],
    )
}

fn proposal_reason(trigger: &str, mismatches: usize, rules: usize) -> String {
    match trigger {
        "training_mismatch_cluster" => {
            format!(
                "build found {mismatches} training mismatch row(s) after deterministic recovery"
            )
        }
        "rule_complexity_budget" => {
            format!("build produced {rules} rules, above the automatic complexity review threshold")
        }
        _ => "automatic proposal trigger fired".to_string(),
    }
}

fn proposal_diagnosis(trigger: &str, candidates: &[ProposalCandidateReport]) -> &'static str {
    if trigger == "rule_complexity_budget" {
        return "rule_complexity";
    }
    if candidates.iter().any(|candidate| {
        candidate.source_stage == "derived_feature_search"
            && candidate.status == ProposalCandidateStatus::Validated
    }) {
        return "missing_relationship_feature";
    }
    if candidates
        .iter()
        .any(|candidate| candidate.status == ProposalCandidateStatus::Validated)
    {
        return "local_rule_gap";
    }
    if candidates
        .iter()
        .any(|candidate| candidate.status == ProposalCandidateStatus::NeedsReview)
    {
        return "needs_semantic_feature_review";
    }
    "unresolved_replay_mismatch"
}

fn recommended_next_phase(trigger: &str, candidates: &[ProposalCandidateReport]) -> &'static str {
    if trigger == "rule_complexity_budget" {
        return "path_map_or_generalization_review";
    }
    if candidates.iter().any(|candidate| {
        candidate.source_stage == "derived_feature_search"
            && candidate.status == ProposalCandidateStatus::Validated
    }) {
        return "promote_derived_feature_to_observer";
    }
    if candidates
        .iter()
        .any(|candidate| candidate.status == ProposalCandidateStatus::Validated)
    {
        return "review_validated_rule_proposals";
    }
    if candidates
        .iter()
        .any(|candidate| candidate.status == ProposalCandidateStatus::NeedsReview)
    {
        return "add_semantic_feature_or_path_map";
    }
    "data_review_or_path_map_search"
}

fn mismatch_summary(mismatches: &[TrainingMismatch]) -> TrainingMismatchSummary {
    let missed_denies = mismatches
        .iter()
        .filter(|mismatch| !mismatch.expected_allowed && mismatch.predicted_allowed)
        .count();
    let false_denies = mismatches
        .iter()
        .filter(|mismatch| mismatch.expected_allowed && !mismatch.predicted_allowed)
        .count();
    TrainingMismatchSummary {
        total_mismatches: mismatches.len(),
        missed_denies,
        false_denies,
    }
}

fn subgroup_rule_candidates(
    rows: &[DecisionTraceRow],
    mismatches: &[TrainingMismatch],
    mismatch_summary: &TrainingMismatchSummary,
) -> Vec<ProposalCandidateReport> {
    let predicted_allowed = proposal_target_allowed(mismatch_summary);
    let mut probes = Vec::new();
    let mut scalar_keys = BTreeSet::new();

    for mismatch in mismatches {
        let Some(row) = rows.get(mismatch.row_index) else {
            continue;
        };
        for (feature, value) in scalar_features(&row.features) {
            let key = (feature.clone(), canonical_value_key(&value));
            if scalar_keys.insert(key) {
                probes.push(CandidateProbe {
                    proposal_id: format!("subgroup_{}_eq", sanitize_id(&feature)),
                    proposal_type: if predicted_allowed {
                        "refinement_region".to_string()
                    } else {
                        "candidate_rule".to_string()
                    },
                    source_stage: "subgroup_discovery".to_string(),
                    reason: "scalar subgroup overlaps replay mismatches".to_string(),
                    recommendation: Some("review_candidate_rule".to_string()),
                    feature_expression: None,
                    suggested_region: region_map([
                        ("feature", Value::String(feature.clone())),
                        ("operator", Value::String("eq".to_string())),
                        ("value", value.clone()),
                    ]),
                    predicted_allowed: Some(predicted_allowed),
                    predicate: ProbePredicate::ScalarEq { feature, value },
                });
            }
        }
    }

    for feature in numeric_feature_names(rows) {
        let values = mismatches
            .iter()
            .filter_map(|mismatch| rows.get(mismatch.row_index))
            .filter_map(|row| numeric_feature(row, &feature))
            .collect::<Vec<_>>();
        if values.is_empty() {
            continue;
        }
        let min = values.iter().copied().fold(f64::INFINITY, f64::min);
        let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        if min.is_finite() && max.is_finite() {
            probes.push(CandidateProbe {
                proposal_id: format!("subgroup_{}_range", sanitize_id(&feature)),
                proposal_type: "candidate_region".to_string(),
                source_stage: "subgroup_discovery".to_string(),
                reason: "numeric range encloses mismatch rows".to_string(),
                recommendation: Some("review_candidate_region".to_string()),
                feature_expression: None,
                suggested_region: region_map([
                    ("feature", Value::String(feature.clone())),
                    ("operator", Value::String("between".to_string())),
                    ("min", json_f64(min)),
                    ("max", json_f64(max)),
                ]),
                predicted_allowed: Some(predicted_allowed),
                predicate: ProbePredicate::NumericRange { feature, min, max },
            });
        }
    }

    validate_probes(rows, mismatches, mismatch_summary, probes)
}

fn derived_feature_candidates(
    rows: &[DecisionTraceRow],
    mismatches: &[TrainingMismatch],
    mismatch_summary: &TrainingMismatchSummary,
) -> Vec<ProposalCandidateReport> {
    let predicted_allowed = proposal_target_allowed(mismatch_summary);
    let features = numeric_feature_names(rows);
    let mut probes = Vec::new();

    for (left_index, left) in features.iter().enumerate() {
        for right in features.iter().skip(left_index + 1) {
            let difference_values = mismatches
                .iter()
                .filter_map(|mismatch| rows.get(mismatch.row_index))
                .filter_map(|row| Some(numeric_feature(row, left)? - numeric_feature(row, right)?))
                .collect::<Vec<_>>();
            for (op, threshold) in representative_thresholds(&difference_values) {
                probes.push(CandidateProbe {
                    proposal_id: format!(
                        "derived_diff_{}_{}_{}_{}",
                        sanitize_id(left),
                        sanitize_id(right),
                        threshold_op_label(op),
                        threshold_id(threshold)
                    ),
                    proposal_type: "derived_feature".to_string(),
                    source_stage: "derived_feature_search".to_string(),
                    reason: "derived numeric difference threshold replay-tested against mismatches"
                        .to_string(),
                    recommendation: Some("promote_to_observer_feature".to_string()),
                    feature_expression: Some(format!("{left} - {right}")),
                    suggested_region: region_map([
                        ("derived_operator", Value::String("difference".to_string())),
                        ("left", Value::String(left.clone())),
                        ("right", Value::String(right.clone())),
                        (
                            "operator",
                            Value::String(threshold_op_label(op).to_string()),
                        ),
                        ("threshold", json_f64(threshold)),
                    ]),
                    predicted_allowed: Some(predicted_allowed),
                    predicate: ProbePredicate::NumericDifferenceThreshold {
                        left: left.clone(),
                        right: right.clone(),
                        op,
                        threshold,
                    },
                });
            }

            let ratio_values = mismatches
                .iter()
                .filter_map(|mismatch| rows.get(mismatch.row_index))
                .filter_map(|row| {
                    let denominator = numeric_feature(row, right)?;
                    if denominator == 0.0 {
                        return None;
                    }
                    Some(numeric_feature(row, left)? / denominator)
                })
                .collect::<Vec<_>>();
            for (op, threshold) in representative_thresholds(&ratio_values) {
                probes.push(CandidateProbe {
                    proposal_id: format!(
                        "derived_ratio_{}_{}_{}_{}",
                        sanitize_id(left),
                        sanitize_id(right),
                        threshold_op_label(op),
                        threshold_id(threshold)
                    ),
                    proposal_type: "derived_feature".to_string(),
                    source_stage: "derived_feature_search".to_string(),
                    reason: "derived numeric ratio threshold replay-tested against mismatches"
                        .to_string(),
                    recommendation: Some("promote_to_observer_feature".to_string()),
                    feature_expression: Some(format!("{left} / {right}")),
                    suggested_region: region_map([
                        ("derived_operator", Value::String("ratio".to_string())),
                        ("numerator", Value::String(left.clone())),
                        ("denominator", Value::String(right.clone())),
                        (
                            "operator",
                            Value::String(threshold_op_label(op).to_string()),
                        ),
                        ("threshold", json_f64(threshold)),
                    ]),
                    predicted_allowed: Some(predicted_allowed),
                    predicate: ProbePredicate::NumericRatioThreshold {
                        numerator: left.clone(),
                        denominator: right.clone(),
                        op,
                        threshold,
                    },
                });
            }
        }
    }

    validate_probes(rows, mismatches, mismatch_summary, probes)
}

fn interpretable_model_candidates(
    rows: &[DecisionTraceRow],
    mismatches: &[TrainingMismatch],
    mismatch_summary: &TrainingMismatchSummary,
) -> Vec<ProposalCandidateReport> {
    let predicted_allowed = proposal_target_allowed(mismatch_summary);
    let mut probes = Vec::new();
    for feature in numeric_feature_names(rows) {
        let values = rows
            .iter()
            .filter_map(|row| numeric_feature(row, &feature))
            .collect::<Vec<_>>();
        for (op, threshold) in representative_thresholds(&values) {
            probes.push(CandidateProbe {
                proposal_id: format!(
                    "stump_{}_{}_{}",
                    sanitize_id(&feature),
                    threshold_op_label(op),
                    threshold_id(threshold)
                ),
                proposal_type: "interpretable_model".to_string(),
                source_stage: "interpretable_model_search".to_string(),
                reason: "one-feature decision stump replay-tested against training rows"
                    .to_string(),
                recommendation: Some("review_interpretable_residual".to_string()),
                feature_expression: Some(format!(
                    "{} {} {}",
                    feature,
                    threshold_op_label(op),
                    threshold
                )),
                suggested_region: region_map([
                    ("model", Value::String("decision_stump".to_string())),
                    ("feature", Value::String(feature.clone())),
                    (
                        "operator",
                        Value::String(threshold_op_label(op).to_string()),
                    ),
                    ("threshold", json_f64(threshold)),
                ]),
                predicted_allowed: Some(predicted_allowed),
                predicate: ProbePredicate::NumericThreshold {
                    feature: feature.clone(),
                    op,
                    threshold,
                },
            });
        }
    }
    validate_probes(rows, mismatches, mismatch_summary, probes)
}

fn validate_probes(
    rows: &[DecisionTraceRow],
    mismatches: &[TrainingMismatch],
    mismatch_summary: &TrainingMismatchSummary,
    probes: Vec<CandidateProbe>,
) -> Vec<ProposalCandidateReport> {
    let mismatch_by_row = mismatches
        .iter()
        .map(|mismatch| (mismatch.row_index, mismatch))
        .collect::<HashMap<_, _>>();

    probes
        .into_iter()
        .filter_map(|probe| {
            let mut covered_rows = 0usize;
            let mut covered_mismatch_rows = Vec::new();
            let mut fixed_mismatches = 0usize;
            let mut introduced_mismatches = 0usize;

            for (row_index, row) in rows.iter().enumerate() {
                if !probe_matches(&probe.predicate, row) {
                    continue;
                }
                covered_rows += 1;
                if let Some(mismatch) = mismatch_by_row.get(&row_index) {
                    covered_mismatch_rows.push(row_index);
                    if probe.predicted_allowed == Some(mismatch.expected_allowed) {
                        fixed_mismatches += 1;
                    }
                } else if let Some(predicted_allowed) = probe.predicted_allowed {
                    if predicted_allowed != row.allowed {
                        introduced_mismatches += 1;
                    }
                }
            }

            if fixed_mismatches == 0 && probe.predicted_allowed.is_some() {
                return None;
            }

            let direct_deny_rule = probe.predicted_allowed == Some(false);
            let memorization_probe = is_id_like_singleton_probe(&probe, covered_rows);
            let status = if probe.predicted_allowed.is_none() {
                ProposalCandidateStatus::NeedsReview
            } else if introduced_mismatches > 0 {
                ProposalCandidateStatus::Rejected
            } else if memorization_probe {
                ProposalCandidateStatus::NeedsReview
            } else if direct_deny_rule {
                ProposalCandidateStatus::Validated
            } else {
                ProposalCandidateStatus::NeedsReview
            };
            let passed =
                matches!(status, ProposalCandidateStatus::Validated) && introduced_mismatches == 0;
            let detail = match status {
                ProposalCandidateStatus::Validated => {
                    "deterministic replay found no introduced training mismatches".to_string()
                }
                ProposalCandidateStatus::NeedsReview => {
                    if memorization_probe {
                        "deterministic replay found useful coverage, but singleton or id-like proposals need a semantic feature before promotion"
                            .to_string()
                    } else {
                        "deterministic replay found useful coverage, but proposal needs compilation context"
                            .to_string()
                    }
                }
                ProposalCandidateStatus::Rejected => {
                    "deterministic replay found introduced training mismatches".to_string()
                }
            };

            Some(ProposalCandidateReport {
                proposal_id: probe.proposal_id,
                proposal_type: probe.proposal_type,
                source_stage: probe.source_stage,
                status,
                recommendation: probe.recommendation,
                feature_expression: probe.feature_expression,
                reason: probe.reason,
                suggested_region: probe.suggested_region,
                evidence: ProposalEvidenceReport {
                    fixed_mismatches,
                    introduced_mismatches,
                    covered_rows,
                    covered_mismatch_rows,
                    mismatch_summary: mismatch_summary.clone(),
                },
                validation: ProposalValidationReport {
                    validator: "training_replay".to_string(),
                    deterministic: true,
                    passed,
                    detail,
                },
            })
        })
        .collect()
}

fn proposal_target_allowed(mismatch_summary: &TrainingMismatchSummary) -> bool {
    mismatch_summary.false_denies > mismatch_summary.missed_denies
}

fn derived_feature_from_candidate(
    candidate: &ProposalCandidateReport,
) -> Option<(String, DerivedFeatureDefinition)> {
    let operator = candidate
        .suggested_region
        .get("derived_operator")
        .and_then(Value::as_str)?;
    let (op, left, right, suffix) = match operator {
        "ratio" => (
            DerivedFeatureOperator::Ratio,
            candidate
                .suggested_region
                .get("numerator")
                .and_then(Value::as_str)?,
            candidate
                .suggested_region
                .get("denominator")
                .and_then(Value::as_str)?,
            "over",
        ),
        "difference" => (
            DerivedFeatureOperator::Difference,
            candidate
                .suggested_region
                .get("left")
                .and_then(Value::as_str)?,
            candidate
                .suggested_region
                .get("right")
                .and_then(Value::as_str)?,
            "minus",
        ),
        _ => return None,
    };
    Some((
        format!(
            "derived__{}__{}__{}",
            sanitize_feature_id(left),
            suffix,
            sanitize_feature_id(right)
        ),
        DerivedFeatureDefinition {
            op,
            left_feature: left.to_string(),
            right_feature: right.to_string(),
        },
    ))
}

fn ensure_gate_feature(
    gate: &mut LogicPearlGateIr,
    feature_id: &str,
    derived: DerivedFeatureDefinition,
    feature_expression: Option<&str>,
) {
    if gate
        .input_schema
        .features
        .iter()
        .any(|feature| feature.id == feature_id)
    {
        return;
    }
    gate.input_schema.features.push(FeatureDefinition {
        id: feature_id.to_string(),
        feature_type: FeatureType::Float,
        description: feature_expression
            .map(|expression| format!("Auto-adopted proposal-derived feature: {expression}")),
        values: None,
        min: None,
        max: None,
        editable: Some(false),
        semantics: None,
        governance: None,
        derived: Some(derived),
    });
}

fn comparison_operator_from_label(label: &str) -> Option<ComparisonOperator> {
    match label {
        "gte" => Some(ComparisonOperator::Gte),
        "lte" => Some(ComparisonOperator::Lte),
        "gt" => Some(ComparisonOperator::Gt),
        "lt" => Some(ComparisonOperator::Lt),
        "eq" => Some(ComparisonOperator::Eq),
        _ => None,
    }
}

fn adopted_rule_evidence(
    rows: &[DecisionTraceRow],
    candidate: &ProposalCandidateReport,
) -> RuleEvidence {
    let example_traces = candidate
        .evidence
        .covered_mismatch_rows
        .iter()
        .filter_map(|row_index| rows.get(*row_index))
        .take(3)
        .map(|row| {
            row.trace_provenance
                .as_ref()
                .map(|provenance| RuleTraceEvidence {
                    trace_row_hash: provenance.trace_row_hash.clone(),
                    source_id: provenance.source_id.clone(),
                    source_anchor: provenance.source_anchor.clone(),
                    citation: provenance.citation.clone(),
                    quote_hash: provenance.quote_hash.clone(),
                })
                .unwrap_or_else(|| RuleTraceEvidence {
                    trace_row_hash: crate::decision_trace_row_hash(&row.features, row.allowed),
                    source_id: None,
                    source_anchor: None,
                    citation: None,
                    quote_hash: None,
                })
        })
        .collect();
    RuleEvidence {
        schema_version: "logicpearl.rule_evidence.v1".to_string(),
        support: RuleSupportEvidence {
            denied_trace_count: candidate.evidence.covered_rows,
            allowed_trace_count: candidate.evidence.introduced_mismatches,
            example_traces,
        },
    }
}

fn complexity_review_candidate(
    rule_count: usize,
    mismatch_summary: &TrainingMismatchSummary,
) -> ProposalCandidateReport {
    let suggested_region = region_map([
        ("rule_count", json_number(rule_count)),
        (
            "review",
            Value::String("look for derived features or sub-pearl regions".to_string()),
        ),
    ]);
    ProposalCandidateReport {
        proposal_id: "auto_complexity_review".to_string(),
        proposal_type: "complexity_review".to_string(),
        source_stage: "rule_complexity".to_string(),
        status: ProposalCandidateStatus::NeedsReview,
        recommendation: Some("review_path_map_or_generalization".to_string()),
        feature_expression: None,
        reason: "rule count exceeded the automatic complexity review budget".to_string(),
        suggested_region,
        evidence: ProposalEvidenceReport {
            fixed_mismatches: 0,
            introduced_mismatches: 0,
            covered_rows: 0,
            covered_mismatch_rows: Vec::new(),
            mismatch_summary: mismatch_summary.clone(),
        },
        validation: ProposalValidationReport {
            validator: "complexity_budget".to_string(),
            deterministic: true,
            passed: false,
            detail: "complexity candidates are advisory until a concrete candidate is validated"
                .to_string(),
        },
    }
}

fn compare_candidate_reports(
    left: &ProposalCandidateReport,
    right: &ProposalCandidateReport,
) -> std::cmp::Ordering {
    status_rank(right)
        .cmp(&status_rank(left))
        .then_with(|| {
            right
                .evidence
                .fixed_mismatches
                .cmp(&left.evidence.fixed_mismatches)
        })
        .then_with(|| {
            left.evidence
                .introduced_mismatches
                .cmp(&right.evidence.introduced_mismatches)
        })
        .then_with(|| left.source_stage.cmp(&right.source_stage))
        .then_with(|| left.proposal_id.cmp(&right.proposal_id))
}

fn status_rank(candidate: &ProposalCandidateReport) -> usize {
    match candidate.status {
        ProposalCandidateStatus::Validated => 3,
        ProposalCandidateStatus::NeedsReview => 2,
        ProposalCandidateStatus::Rejected => 1,
    }
}

fn dedupe_candidates(candidates: Vec<ProposalCandidateReport>) -> Vec<ProposalCandidateReport> {
    let mut by_signature = BTreeMap::<String, ProposalCandidateReport>::new();
    for candidate in candidates {
        let signature = serde_json::to_string(&candidate.suggested_region)
            .unwrap_or_else(|_| candidate.proposal_id.clone());
        match by_signature.get(&signature) {
            Some(existing)
                if compare_candidate_reports(&candidate, existing) != std::cmp::Ordering::Less => {}
            _ => {
                by_signature.insert(signature, candidate);
            }
        }
    }
    by_signature.into_values().collect()
}

fn probe_matches(predicate: &ProbePredicate, row: &DecisionTraceRow) -> bool {
    match predicate {
        ProbePredicate::ScalarEq { feature, value } => row.features.get(feature) == Some(value),
        ProbePredicate::NumericRange { feature, min, max } => {
            numeric_feature(row, feature).is_some_and(|value| value >= *min && value <= *max)
        }
        ProbePredicate::NumericThreshold {
            feature,
            op,
            threshold,
        } => numeric_feature(row, feature)
            .is_some_and(|value| threshold_matches(value, *op, *threshold)),
        ProbePredicate::NumericRatioThreshold {
            numerator,
            denominator,
            op,
            threshold,
        } => {
            let Some(denominator_value) = numeric_feature(row, denominator) else {
                return false;
            };
            if denominator_value == 0.0 {
                return false;
            }
            let Some(numerator_value) = numeric_feature(row, numerator) else {
                return false;
            };
            threshold_matches(numerator_value / denominator_value, *op, *threshold)
        }
        ProbePredicate::NumericDifferenceThreshold {
            left,
            right,
            op,
            threshold,
        } => {
            let Some(left_value) = numeric_feature(row, left) else {
                return false;
            };
            let Some(right_value) = numeric_feature(row, right) else {
                return false;
            };
            threshold_matches(left_value - right_value, *op, *threshold)
        }
    }
}

fn is_id_like_singleton_probe(probe: &CandidateProbe, covered_rows: usize) -> bool {
    if covered_rows > 1 {
        return false;
    }
    match &probe.predicate {
        ProbePredicate::ScalarEq { feature, value } => {
            value.is_string()
                && matches!(
                    feature.to_ascii_lowercase().as_str(),
                    "id" | "case_id" | "row_id" | "trace_id" | "record_id" | "request_id"
                )
        }
        _ => false,
    }
}

fn threshold_matches(value: f64, op: ThresholdOp, threshold: f64) -> bool {
    match op {
        ThresholdOp::Gte => value >= threshold,
        ThresholdOp::Lte => value <= threshold,
    }
}

fn representative_thresholds(values: &[f64]) -> Vec<(ThresholdOp, f64)> {
    let mut sorted = values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .collect::<Vec<_>>();
    sorted.sort_by(f64::total_cmp);
    sorted.dedup_by(|left, right| (*left - *right).abs() < f64::EPSILON);
    if sorted.is_empty() {
        return Vec::new();
    }
    let step = (sorted.len() / MAX_THRESHOLDS_PER_FEATURE).max(1);
    sorted
        .into_iter()
        .step_by(step)
        .take(MAX_THRESHOLDS_PER_FEATURE)
        .flat_map(|threshold| [(ThresholdOp::Gte, threshold), (ThresholdOp::Lte, threshold)])
        .collect()
}

fn numeric_feature_names(rows: &[DecisionTraceRow]) -> Vec<String> {
    let mut counts = BTreeMap::<String, usize>::new();
    for row in rows {
        for (feature, value) in &row.features {
            if value.as_f64().is_some() {
                *counts.entry(feature.clone()).or_default() += 1;
            }
        }
    }
    let mut ranked = counts.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked
        .into_iter()
        .take(MAX_NUMERIC_FEATURES)
        .map(|(feature, _count)| feature)
        .collect()
}

fn numeric_feature(row: &DecisionTraceRow, feature: &str) -> Option<f64> {
    row.features.get(feature)?.as_f64()
}

fn scalar_features(features: &HashMap<String, Value>) -> Vec<(String, Value)> {
    features
        .iter()
        .filter(|(_feature, value)| {
            value.is_boolean() || value.is_number() || value.is_string() || value.is_null()
        })
        .map(|(feature, value)| (feature.clone(), value.clone()))
        .collect()
}

fn stage_report<const N: usize>(
    name: impl Into<String>,
    status: ProposalStageStatus,
    detail: Option<String>,
    candidates_produced: usize,
    metrics: [(&str, Value); N],
) -> ProposalStageReport {
    ProposalStageReport {
        name: name.into(),
        status,
        detail,
        candidates_produced,
        metrics: metrics
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    }
}

fn region_map<const N: usize>(items: [(&str, Value); N]) -> BTreeMap<String, Value> {
    items
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

fn canonical_feature_signature(features: &HashMap<String, Value>) -> String {
    let ordered = features
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    serde_json::to_string(&ordered).unwrap_or_else(|_| "{}".to_string())
}

fn canonical_value_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

fn json_number(value: usize) -> Value {
    Value::Number(Number::from(value))
}

fn json_f64(value: f64) -> Value {
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

fn threshold_op_label(op: ThresholdOp) -> &'static str {
    match op {
        ThresholdOp::Gte => "gte",
        ThresholdOp::Lte => "lte",
    }
}

fn threshold_id(value: f64) -> String {
    let sign = if value.is_sign_negative() {
        "neg"
    } else {
        "pos"
    };
    format!("{sign}_{:.6}", value.abs()).replace('.', "_")
}

fn sanitize_id(value: &str) -> String {
    let mut sanitized = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else if !sanitized.ends_with('_') {
            sanitized.push('_');
        }
    }
    sanitized.trim_matches('_').to_string()
}

fn sanitize_feature_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}
