// SPDX-License-Identifier: MIT
use super::super::canonicalize::{comparison_matches, expression_matches};
use super::super::features::{
    is_derived_feature_name, numeric_feature_names, sorted_feature_names,
};
use super::super::rule_text::{generate_rule_text, RuleTextContext};
use super::super::{
    report_progress, CandidateRule, DecisionTraceRow, DiscoveryDecisionMode, ProgressCallback,
    ResidualPassOptions,
};
use super::{
    CONJUNCTION_ATOM_FRONTIER_LIMIT, NUMERIC_EQ_MAX_DISTINCT_VALUES,
    NUMERIC_EQ_MIN_SUPPORT_ABSOLUTE, NUMERIC_EQ_MIN_SUPPORT_BASIS_POINTS,
};
use logicpearl_ir::{
    BooleanEvidencePolicy, ComparisonExpression, ComparisonOperator, ComparisonValue, Expression,
    FeatureGovernance, RuleDefinition, RuleKind, RuleVerificationStatus,
};
use logicpearl_verify::{
    synthesize_boolean_conjunctions, BooleanConjunctionCandidate, BooleanConjunctionSearchOptions,
    BooleanSearchExample,
};
use serde_json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const CONJUNCTION_SYNTHESIS_HEARTBEAT: Duration = Duration::from_secs(30);

#[cfg(test)]
pub(super) fn candidate_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
    progress: Option<&ProgressCallback<'_>>,
) -> Vec<CandidateRule> {
    candidate_rules_with_cache(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
        residual_options,
        progress,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn candidate_rules_with_cache(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
    progress: Option<&ProgressCallback<'_>>,
    match_cache: Option<&CandidateMatchCache<'_>>,
) -> Vec<CandidateRule> {
    let mut candidates = atomic_candidate_rules(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
        progress,
        match_cache,
    );
    candidates.retain(|candidate| candidate.denied_coverage > 0);
    candidates.sort_by(compare_candidate_priority);
    candidates.dedup_by(|left, right| left.signature() == right.signature());
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: {} atomic candidate rules retained",
            candidates.len()
        ),
    );
    if let Some(options) = residual_options {
        candidates.extend(conjunction_candidate_rules_with_cache(
            rows,
            denied_indices,
            allowed_indices,
            &candidates,
            options,
            progress,
            match_cache,
        ));
    }

    candidates.sort_by(compare_candidate_priority);
    candidates.dedup_by(|left, right| left.signature() == right.signature());
    candidates
}

fn atomic_candidate_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    progress: Option<&ProgressCallback<'_>>,
    match_cache: Option<&CandidateMatchCache<'_>>,
) -> Vec<CandidateRule> {
    let feature_names = sorted_feature_names(rows);
    let numeric_features = numeric_feature_names(rows)
        .into_iter()
        .filter(|feature| feature_has_nontrivial_numeric_range(rows, feature))
        .collect::<Vec<_>>();
    let feature_ref_numeric_features = numeric_features
        .iter()
        .filter(|feature| !is_derived_feature_name(feature))
        .cloned()
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    let feature_total = feature_names.len();
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: enumerating atomic predicates across {feature_total} features"
        ),
    );

    for (feature_index, feature) in feature_names.into_iter().enumerate() {
        let values: Vec<&Value> = rows
            .iter()
            .filter_map(|row| row.features.get(&feature))
            .collect();
        if values.iter().all(|value| value.is_number()) {
            let unique_thresholds = numeric_thresholds(rows, denied_indices, &feature);
            let allow_numeric_eq = numeric_feature_supports_exact_match(rows, &feature);
            let min_numeric_eq_support = numeric_eq_min_support(denied_indices.len());
            let mut numeric_checks = 0usize;
            let numeric_total = unique_thresholds.len() * 5;
            for threshold in unique_thresholds {
                for op in [
                    ComparisonOperator::Lt,
                    ComparisonOperator::Lte,
                    ComparisonOperator::Eq,
                    ComparisonOperator::Gte,
                    ComparisonOperator::Gt,
                ] {
                    let comparison = ComparisonExpression {
                        feature: feature.clone(),
                        op: op.clone(),
                        value: ComparisonValue::Literal(Value::Number(
                            Number::from_f64(threshold).unwrap(),
                        )),
                    };
                    let candidate = candidate_from_expression(
                        rows,
                        denied_indices,
                        allowed_indices,
                        Expression::Comparison(comparison.clone()),
                        match_cache,
                    );
                    let skip_numeric_eq = comparison.op == ComparisonOperator::Eq
                        && comparison.value.literal().and_then(Value::as_f64).is_some()
                        && (!allow_numeric_eq
                            || candidate.denied_coverage < min_numeric_eq_support);
                    if !skip_numeric_eq && candidate_allowed_for_mode(&candidate, decision_mode) {
                        candidates.push(candidate);
                    }
                    numeric_checks += 1;
                    report_candidate_subphase_progress(
                        progress,
                        "numeric predicates",
                        numeric_checks,
                        numeric_total,
                        Some(&feature),
                        candidates.len(),
                    );
                }
            }
        } else if values.iter().all(|value| value.is_boolean()) {
            let unique_values: BTreeSet<bool> = rows
                .iter()
                .filter_map(|row| row.features.get(&feature))
                .filter_map(Value::as_bool)
                .collect();
            for boolean in unique_values {
                if !boolean_candidate_allowed(feature_governance.get(&feature), boolean) {
                    continue;
                }
                let candidate = candidate_from_expression(
                    rows,
                    denied_indices,
                    allowed_indices,
                    Expression::Comparison(ComparisonExpression {
                        feature: feature.clone(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::Bool(boolean)),
                    }),
                    match_cache,
                );
                if candidate_allowed_for_mode(&candidate, decision_mode) {
                    candidates.push(candidate);
                }
            }
        } else {
            let unique_values: BTreeSet<String> = rows
                .iter()
                .filter_map(|row| row.features.get(&feature))
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect();
            for text in unique_values {
                let candidate = candidate_from_expression(
                    rows,
                    denied_indices,
                    allowed_indices,
                    Expression::Comparison(ComparisonExpression {
                        feature: feature.clone(),
                        op: ComparisonOperator::Eq,
                        value: ComparisonValue::Literal(Value::String(text.clone())),
                    }),
                    match_cache,
                );
                if candidate_allowed_for_mode(&candidate, decision_mode) {
                    candidates.push(candidate);
                }
            }
        }
        report_candidate_subphase_progress(
            progress,
            "atomic features",
            feature_index + 1,
            feature_total,
            Some(&feature),
            candidates.len(),
        );
    }

    let feature_ref_total = feature_ref_numeric_features
        .len()
        .saturating_mul(feature_ref_numeric_features.len().saturating_sub(1))
        .saturating_mul(4);
    let mut feature_ref_checks = 0usize;
    for left in &feature_ref_numeric_features {
        for right in &feature_ref_numeric_features {
            if left == right {
                continue;
            }
            for op in [
                ComparisonOperator::Lt,
                ComparisonOperator::Lte,
                ComparisonOperator::Gt,
                ComparisonOperator::Gte,
            ] {
                let candidate = candidate_from_expression(
                    rows,
                    denied_indices,
                    allowed_indices,
                    Expression::Comparison(ComparisonExpression {
                        feature: left.clone(),
                        op,
                        value: ComparisonValue::FeatureRef {
                            feature_ref: right.clone(),
                        },
                    }),
                    match_cache,
                );
                if candidate_allowed_for_mode(&candidate, decision_mode) {
                    candidates.push(candidate);
                }
                feature_ref_checks += 1;
                report_candidate_subphase_progress(
                    progress,
                    "feature-reference predicates",
                    feature_ref_checks,
                    feature_ref_total,
                    Some(left),
                    candidates.len(),
                );
            }
        }
    }

    candidates
}

#[cfg(test)]
pub(super) fn conjunction_candidate_rules(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    atomic_candidates: &[CandidateRule],
    options: &ResidualPassOptions,
    progress: Option<&ProgressCallback<'_>>,
) -> Vec<CandidateRule> {
    conjunction_candidate_rules_with_cache(
        rows,
        denied_indices,
        allowed_indices,
        atomic_candidates,
        options,
        progress,
        None,
    )
}

fn conjunction_candidate_rules_with_cache(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    atomic_candidates: &[CandidateRule],
    options: &ResidualPassOptions,
    progress: Option<&ProgressCallback<'_>>,
    match_cache: Option<&CandidateMatchCache<'_>>,
) -> Vec<CandidateRule> {
    let mut prioritized_atoms = atomic_candidates
        .iter()
        .filter(|candidate| candidate_as_comparison(candidate).is_some())
        .collect::<Vec<_>>();
    prioritized_atoms.sort_by(|left, right| compare_conjunction_atom_priority(left, right));
    let atomic_comparisons = prioritized_atoms
        .into_iter()
        .take(CONJUNCTION_ATOM_FRONTIER_LIMIT)
        .filter_map(candidate_as_comparison)
        .cloned()
        .collect::<Vec<_>>();
    if atomic_comparisons.len() < 2 {
        return Vec::new();
    }
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: synthesizing boolean conjunctions from {} atoms (max_conditions={}, max_rules={})",
            atomic_comparisons.len(),
            options.max_conditions,
            options.max_rules
        ),
    );

    let atom_ids = atomic_comparisons
        .iter()
        .enumerate()
        .map(|(index, _)| format!("atom_{index:03}"))
        .collect::<Vec<_>>();
    let examples = denied_indices
        .iter()
        .map(|index| BooleanSearchExample {
            features: conjunction_example_features(
                &rows[*index].features,
                &atom_ids,
                &atomic_comparisons,
            ),
            positive: true,
        })
        .chain(allowed_indices.iter().map(|index| BooleanSearchExample {
            features: conjunction_example_features(
                &rows[*index].features,
                &atom_ids,
                &atomic_comparisons,
            ),
            positive: false,
        }))
        .collect::<Vec<_>>();

    let conjunctions = match synthesize_boolean_conjunctions_with_progress(
        &examples,
        &BooleanConjunctionSearchOptions {
            min_conditions: 2,
            max_conditions: options.max_conditions,
            min_positive_support: options.min_positive_support,
            max_negative_hits: options.max_negative_hits,
            max_rules: options.max_rules,
        },
        progress,
    ) {
        Ok(conjunctions) => conjunctions,
        Err(err) => {
            #[cfg(not(test))]
            let _ = &err;
            #[cfg(test)]
            eprintln!("conjunction synthesis failed: {err}");
            return Vec::new();
        }
    };
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: synthesized {} boolean conjunctions",
            conjunctions.len()
        ),
    );

    let atom_lookup = atom_ids
        .iter()
        .cloned()
        .zip(atomic_comparisons.iter().cloned())
        .collect::<BTreeMap<_, _>>();
    conjunctions
        .into_iter()
        .filter_map(|candidate| {
            let comparisons = candidate
                .required_true_features
                .iter()
                .filter_map(|atom_id| atom_lookup.get(atom_id).cloned())
                .collect::<Vec<_>>();
            if comparisons.is_empty() {
                return None;
            }
            Some(candidate_from_expression(
                rows,
                denied_indices,
                allowed_indices,
                conjunction_expression(comparisons),
                match_cache,
            ))
        })
        .collect()
}

fn synthesize_boolean_conjunctions_with_progress(
    examples: &[BooleanSearchExample],
    options: &BooleanConjunctionSearchOptions,
    progress: Option<&ProgressCallback<'_>>,
) -> logicpearl_core::Result<Vec<BooleanConjunctionCandidate>> {
    let Some(progress) = progress else {
        return synthesize_boolean_conjunctions(examples, options);
    };
    let started = Instant::now();
    std::thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        scope.spawn(move || {
            loop {
                match done_rx.recv_timeout(CONJUNCTION_SYNTHESIS_HEARTBEAT) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => report_progress(
                        Some(progress),
                        "candidate_generation",
                        format!(
                            "candidate_generation: synthesizing boolean conjunctions still running (elapsed={}s)",
                            started.elapsed().as_secs()
                        ),
                    ),
                }
            }
        });
        let result = synthesize_boolean_conjunctions(examples, options);
        let _ = done_tx.send(());
        result
    })
}

fn report_candidate_subphase_progress(
    progress: Option<&ProgressCallback<'_>>,
    subphase: &str,
    completed: usize,
    total: usize,
    current: Option<&str>,
    candidate_count: usize,
) {
    if total == 0 || !crossed_progress_bucket(completed, total) {
        return;
    }
    let percent = completed.saturating_mul(100) / total;
    let current = current
        .map(|value| format!("; current={value}"))
        .unwrap_or_default();
    report_progress(
        progress,
        "candidate_generation",
        format!(
            "candidate_generation: {subphase} {completed}/{total} ({percent}%); candidates={candidate_count}{current}"
        ),
    );
}

fn crossed_progress_bucket(completed: usize, total: usize) -> bool {
    if completed == 0 || completed == total {
        return completed == total;
    }
    let previous_bucket = completed.saturating_sub(1).saturating_mul(10) / total;
    let current_bucket = completed.saturating_mul(10) / total;
    current_bucket != previous_bucket
}

fn compare_conjunction_atom_priority(left: &CandidateRule, right: &CandidateRule) -> Ordering {
    left.false_positives
        .cmp(&right.false_positives)
        .then_with(|| right.denied_coverage.cmp(&left.denied_coverage))
        .then_with(|| {
            candidate_complexity_penalty(left, DiscoveryDecisionMode::Standard).cmp(
                &candidate_complexity_penalty(right, DiscoveryDecisionMode::Standard),
            )
        })
        .then_with(|| left.signature().cmp(right.signature()))
}

fn conjunction_example_features(
    row_features: &HashMap<String, Value>,
    atom_ids: &[String],
    comparisons: &[ComparisonExpression],
) -> BTreeMap<String, bool> {
    atom_ids
        .iter()
        .cloned()
        .zip(
            comparisons
                .iter()
                .map(|comparison| comparison_matches(comparison, row_features)),
        )
        .collect()
}

fn comparison_sort_key(c: &ComparisonExpression) -> (String, String, String) {
    (
        c.feature.clone(),
        format!("{:?}", c.op),
        serde_json::to_string(&c.value).unwrap_or_default(),
    )
}

fn conjunction_expression(mut comparisons: Vec<ComparisonExpression>) -> Expression {
    comparisons.sort_by_key(comparison_sort_key);
    if comparisons.len() == 1 {
        return Expression::Comparison(comparisons.pop().expect("single comparison"));
    }
    Expression::All {
        all: comparisons
            .into_iter()
            .map(Expression::Comparison)
            .collect(),
    }
}

fn candidate_from_expression(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    expression: Expression,
    match_cache: Option<&CandidateMatchCache<'_>>,
) -> CandidateRule {
    let denied_coverage = match match_cache {
        Some(cache) => cache.coverage_for_expression(denied_indices, &expression),
        None => candidate_coverage(rows, denied_indices, &expression),
    };
    let false_positives = match match_cache {
        Some(cache) => cache.coverage_for_expression(allowed_indices, &expression),
        None => candidate_coverage(rows, allowed_indices, &expression),
    };
    CandidateRule::new_with_population(
        expression,
        denied_coverage,
        false_positives,
        denied_indices.len(),
        allowed_indices.len(),
    )
}

pub(super) fn candidate_as_comparison(candidate: &CandidateRule) -> Option<&ComparisonExpression> {
    match &candidate.expression {
        Expression::Comparison(comparison) => Some(comparison),
        _ => None,
    }
}

pub(super) fn candidate_is_compound(candidate: &CandidateRule) -> bool {
    !matches!(candidate.expression, Expression::Comparison(_))
}

fn boolean_candidate_allowed(governance: Option<&FeatureGovernance>, value: bool) -> bool {
    match governance.and_then(|governance| governance.deny_boolean_evidence.as_ref()) {
        None | Some(BooleanEvidencePolicy::Either) => true,
        Some(BooleanEvidencePolicy::TrueOnly) => value,
        Some(BooleanEvidencePolicy::FalseOnly) => !value,
        Some(BooleanEvidencePolicy::Never) => false,
    }
}

pub(super) fn best_immediate_candidate_rule_with_cache(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
    feature_governance: &BTreeMap<String, FeatureGovernance>,
    decision_mode: DiscoveryDecisionMode,
    residual_options: Option<&ResidualPassOptions>,
    match_cache: &CandidateMatchCache<'_>,
) -> Option<CandidateRule> {
    candidate_rules_with_cache(
        rows,
        denied_indices,
        allowed_indices,
        feature_governance,
        decision_mode,
        residual_options,
        None,
        Some(match_cache),
    )
    .into_iter()
    .next()
}

#[derive(Debug)]
pub(super) struct CandidateMatchCache<'a> {
    rows: &'a [DecisionTraceRow],
    matches_by_signature: Mutex<HashMap<String, Arc<Vec<bool>>>>,
    complexity_by_signature: Mutex<HashMap<String, usize>>,
}

impl<'a> CandidateMatchCache<'a> {
    pub(super) fn new(rows: &'a [DecisionTraceRow]) -> Self {
        Self {
            rows,
            matches_by_signature: Mutex::new(HashMap::new()),
            complexity_by_signature: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn matches_candidate(&self, row_index: usize, candidate: &CandidateRule) -> bool {
        self.mask_for_candidate(candidate)[row_index]
    }

    pub(super) fn rows(&self) -> &[DecisionTraceRow] {
        self.rows
    }

    pub(super) fn coverage_for_expression(
        &self,
        indices: &[usize],
        expression: &Expression,
    ) -> usize {
        let mask = self.mask_for_expression(expression);
        indices.iter().filter(|index| mask[**index]).count()
    }

    pub(super) fn complexity_penalty(
        &self,
        candidate: &CandidateRule,
        decision_mode: DiscoveryDecisionMode,
    ) -> usize {
        let key = format!("{decision_mode:?}:{}", candidate.signature());
        if let Some(penalty) = self
            .complexity_by_signature
            .lock()
            .expect("candidate complexity cache poisoned")
            .get(&key)
            .copied()
        {
            return penalty;
        }
        let penalty = candidate_complexity_penalty(candidate, decision_mode);
        *self
            .complexity_by_signature
            .lock()
            .expect("candidate complexity cache poisoned")
            .entry(key)
            .or_insert(penalty)
    }

    fn mask_for_candidate(&self, candidate: &CandidateRule) -> Arc<Vec<bool>> {
        if let Some(mask) = self
            .matches_by_signature
            .lock()
            .expect("candidate match cache poisoned")
            .get(candidate.signature())
            .cloned()
        {
            return mask;
        }
        self.mask_for_expression(&candidate.expression)
    }

    fn mask_for_expression(&self, expression: &Expression) -> Arc<Vec<bool>> {
        let signature = serde_json::to_string(expression).unwrap_or_default();
        if let Some(mask) = self
            .matches_by_signature
            .lock()
            .expect("candidate match cache poisoned")
            .get(&signature)
            .cloned()
        {
            return mask;
        }
        let computed = Arc::new(
            self.rows
                .iter()
                .map(|row| expression_matches(expression, &row.features))
                .collect::<Vec<_>>(),
        );
        self.matches_by_signature
            .lock()
            .expect("candidate match cache poisoned")
            .entry(signature)
            .or_insert_with(|| computed.clone())
            .clone()
    }
}

pub(super) fn compare_candidate_priority(left: &CandidateRule, right: &CandidateRule) -> Ordering {
    let left_net = left.denied_coverage as isize - left.false_positives as isize;
    let right_net = right.denied_coverage as isize - right.false_positives as isize;
    candidate_signal_score(right)
        .total_cmp(&candidate_signal_score(left))
        .then_with(|| right_net.cmp(&left_net))
        .then_with(|| left.false_positives.cmp(&right.false_positives))
        .then_with(|| right.denied_coverage.cmp(&left.denied_coverage))
        .then_with(|| {
            candidate_complexity_penalty(left, DiscoveryDecisionMode::Standard).cmp(
                &candidate_complexity_penalty(right, DiscoveryDecisionMode::Standard),
            )
        })
        .then_with(|| {
            candidate_memorization_penalty(left).cmp(&candidate_memorization_penalty(right))
        })
        .then_with(|| left.signature().cmp(right.signature()))
}

fn candidate_signal_score(candidate: &CandidateRule) -> f64 {
    let denied_total = candidate.denied_total;
    let allowed_total = candidate.allowed_total;
    let matched_denied = candidate.denied_coverage;
    let matched_allowed = candidate.false_positives;
    let matched_total = matched_denied + matched_allowed;
    let total = denied_total + allowed_total;
    if denied_total == 0 || allowed_total == 0 || matched_denied == 0 || matched_total == 0 {
        return 0.0;
    }
    let base_rate = denied_total as f64 / total as f64;
    let precision = matched_denied as f64 / matched_total as f64;
    if precision <= base_rate {
        return 0.0;
    }
    let table = [
        matched_denied,
        matched_allowed,
        denied_total.saturating_sub(matched_denied),
        allowed_total.saturating_sub(matched_allowed),
    ];
    let row_totals = [matched_total, total.saturating_sub(matched_total)];
    let col_totals = [denied_total, allowed_total];
    let mut statistic = 0.0;
    for (row_index, row_total) in row_totals.iter().enumerate() {
        for (col_index, col_total) in col_totals.iter().enumerate() {
            let observed = table[row_index * 2 + col_index];
            if observed == 0 {
                continue;
            }
            let expected = (*row_total as f64 * *col_total as f64) / total as f64;
            if expected > 0.0 {
                statistic += observed as f64 * ((observed as f64) / expected).ln();
            }
        }
    }
    2.0 * statistic
}

pub(super) fn candidate_complexity_penalty(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> usize {
    expression_complexity_penalty(&candidate.expression, decision_mode)
}

pub(super) fn candidate_allowed_for_mode(
    candidate: &CandidateRule,
    decision_mode: DiscoveryDecisionMode,
) -> bool {
    expression_allowed_for_mode(&candidate.expression, decision_mode)
}

pub(super) fn candidate_memorization_penalty(candidate: &CandidateRule) -> usize {
    expression_memorization_penalty(&candidate.expression, candidate.denied_coverage)
}

fn expression_complexity_penalty(
    expression: &Expression,
    decision_mode: DiscoveryDecisionMode,
) -> usize {
    match expression {
        Expression::Comparison(comparison) => {
            if decision_mode == DiscoveryDecisionMode::Review
                && comparison.op == ComparisonOperator::Eq
                && comparison.value.literal().and_then(Value::as_f64).is_some()
            {
                return usize::MAX / 4;
            }
            match &comparison.value {
                ComparisonValue::Literal(value)
                    if comparison.op == ComparisonOperator::Eq && value.as_f64().is_some() =>
                {
                    3
                }
                ComparisonValue::FeatureRef { .. } => 1,
                ComparisonValue::Literal(_) if is_derived_feature_name(&comparison.feature) => 2,
                ComparisonValue::Literal(_) => 0,
            }
        }
        Expression::All { all } => {
            all.iter()
                .map(|child| expression_complexity_penalty(child, decision_mode))
                .sum::<usize>()
                + all.len().saturating_sub(1)
        }
        Expression::Any { any } => {
            any.iter()
                .map(|child| expression_complexity_penalty(child, decision_mode))
                .sum::<usize>()
                + any.len().saturating_sub(1)
        }
        Expression::Not { expr } => expression_complexity_penalty(expr, decision_mode) + 1,
    }
}

fn expression_allowed_for_mode(
    expression: &Expression,
    decision_mode: DiscoveryDecisionMode,
) -> bool {
    match expression {
        Expression::Comparison(comparison) => {
            !(decision_mode == DiscoveryDecisionMode::Review
                && comparison.op == ComparisonOperator::Eq
                && comparison.value.literal().and_then(Value::as_f64).is_some())
        }
        Expression::All { all } => all
            .iter()
            .all(|child| expression_allowed_for_mode(child, decision_mode)),
        Expression::Any { any } => any
            .iter()
            .all(|child| expression_allowed_for_mode(child, decision_mode)),
        Expression::Not { expr } => expression_allowed_for_mode(expr, decision_mode),
    }
}

fn expression_memorization_penalty(expression: &Expression, denied_coverage: usize) -> usize {
    match expression {
        Expression::Comparison(comparison)
            if comparison.op == ComparisonOperator::Eq
                && comparison.value.literal().and_then(Value::as_f64).is_some() =>
        {
            1_000_000usize.saturating_sub(denied_coverage)
        }
        Expression::Comparison(_) => 0,
        Expression::All { all } => all
            .iter()
            .map(|child| expression_memorization_penalty(child, denied_coverage))
            .sum(),
        Expression::Any { any } => any
            .iter()
            .map(|child| expression_memorization_penalty(child, denied_coverage))
            .sum(),
        Expression::Not { expr } => expression_memorization_penalty(expr, denied_coverage),
    }
}

fn numeric_thresholds(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    feature: &str,
) -> Vec<f64> {
    let mut thresholds: BTreeSet<i64> = BTreeSet::new();
    for index in denied_indices {
        if let Some(value) = rows[*index].features.get(feature).and_then(Value::as_f64) {
            thresholds.insert((value * 1000.0).round() as i64);
        }
    }
    thresholds
        .into_iter()
        .map(|scaled| scaled as f64 / 1000.0)
        .collect()
}

fn numeric_feature_supports_exact_match(rows: &[DecisionTraceRow], feature: &str) -> bool {
    numeric_feature_distinct_value_count(rows, feature) <= NUMERIC_EQ_MAX_DISTINCT_VALUES
}

fn numeric_feature_distinct_value_count(rows: &[DecisionTraceRow], feature: &str) -> usize {
    let mut distinct_values: BTreeSet<i64> = BTreeSet::new();
    for value in rows
        .iter()
        .filter_map(|row| row.features.get(feature))
        .filter_map(Value::as_f64)
    {
        distinct_values.insert((value * 1000.0).round() as i64);
    }
    distinct_values.len()
}

fn numeric_eq_min_support(denied_count: usize) -> usize {
    let proportional = denied_count
        .saturating_mul(NUMERIC_EQ_MIN_SUPPORT_BASIS_POINTS)
        .div_ceil(10_000);
    NUMERIC_EQ_MIN_SUPPORT_ABSOLUTE.max(proportional)
}

fn feature_has_nontrivial_numeric_range(rows: &[DecisionTraceRow], feature: &str) -> bool {
    numeric_feature_distinct_value_count(rows, feature) > 2
}

fn candidate_coverage(
    rows: &[DecisionTraceRow],
    indices: &[usize],
    expression: &Expression,
) -> usize {
    indices
        .iter()
        .filter(|index| expression_matches(expression, &rows[**index].features))
        .count()
}

#[cfg(test)]
pub(crate) fn rule_from_candidate(bit: u32, candidate: &CandidateRule) -> RuleDefinition {
    rule_from_candidate_with_context(bit, candidate, &RuleTextContext::empty())
}

pub(super) fn rule_from_candidate_with_context(
    bit: u32,
    candidate: &CandidateRule,
    context: &RuleTextContext<'_>,
) -> RuleDefinition {
    let deny_when = candidate.expression.clone();
    let generated = generate_rule_text(&deny_when, context);
    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when,
        label: generated.label,
        message: generated.message,
        severity: None,
        counterfactual_hint: generated.counterfactual_hint,
        verification_status: Some(RuleVerificationStatus::PipelineUnverified),
        evidence: None,
    }
}

pub(super) fn residual_rule_from_candidate(
    bit: u32,
    candidate: BooleanConjunctionCandidate,
    context: &RuleTextContext<'_>,
) -> RuleDefinition {
    let deny_when = if candidate.required_true_features.len() == 1 {
        Expression::Comparison(ComparisonExpression {
            feature: candidate.required_true_features[0].clone(),
            op: ComparisonOperator::Gt,
            value: ComparisonValue::Literal(Value::Number(Number::from(0))),
        })
    } else {
        Expression::All {
            all: candidate
                .required_true_features
                .iter()
                .map(|feature| {
                    Expression::Comparison(ComparisonExpression {
                        feature: feature.clone(),
                        op: ComparisonOperator::Gt,
                        value: ComparisonValue::Literal(Value::Number(Number::from(0))),
                    })
                })
                .collect(),
        }
    };

    let generated = generate_rule_text(&deny_when, context);
    RuleDefinition {
        id: format!("rule_{bit:03}"),
        kind: RuleKind::Predicate,
        bit,
        deny_when,
        label: generated.label,
        message: generated.message,
        severity: None,
        counterfactual_hint: generated.counterfactual_hint,
        verification_status: Some(RuleVerificationStatus::RefinedUnverified),
        evidence: None,
    }
}

pub(super) fn matches_candidate(
    features: &HashMap<String, Value>,
    candidate: &CandidateRule,
) -> bool {
    expression_matches(&candidate.expression, features)
}
