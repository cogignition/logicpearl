use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::sync::OnceLock;

static BUNDLE_JSON: &str = include_str!("../../generated/mkh_corpus_bundle.json");
static BUNDLE: OnceLock<CorpusBundle> = OnceLock::new();

fn bundle() -> &'static CorpusBundle {
    BUNDLE.get_or_init(|| serde_json::from_str(BUNDLE_JSON).expect("valid mkh corpus bundle"))
}

#[derive(Debug, Deserialize)]
struct CorpusBundle {
    artifact_id: String,
    policy_count: usize,
    policies: Vec<PolicySpec>,
}

#[derive(Debug, Deserialize)]
struct PolicySpec {
    policy_id: String,
    title: String,
    sources: Vec<PolicySource>,
    requirements: Vec<RequirementSpec>,
    clusters: Vec<ClusterSpec>,
}

#[derive(Debug, Deserialize)]
struct PolicySource {
    source_id: String,
    title: String,
    section_note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementSpec {
    requirement_id: String,
    question_text: String,
    kind: String,
    cluster_id: String,
    evidence_needed: String,
    source_excerpt: String,
    source_id: String,
    source_anchor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClusterSpec {
    cluster_id: String,
    label: String,
    kind: String,
    codes: Vec<String>,
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct HealthcarePolicyRequest {
    request: RequestContext,
    #[serde(default)]
    submission: Option<SubmissionMetadata>,
    #[serde(default)]
    policy_context: Option<PolicyContext>,
    #[serde(default)]
    guided_questions: Vec<GuidedQuestion>,
    #[serde(default)]
    structured_history: Option<StructuredHistory>,
    #[serde(default)]
    clinical_documents: Vec<EvidenceDocument>,
    #[serde(default)]
    member_evidence: MemberEvidence,
}

#[derive(Debug, Deserialize, Default)]
struct RequestContext {
    request_id: String,
    payer: String,
    member_id: String,
    requested_service: RequestedService,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    line_of_business: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RequestedService {
    kind: String,
    code: String,
    label: String,
}

#[derive(Debug, Deserialize, Default)]
struct SubmissionMetadata {
    #[serde(default)]
    submission_id: String,
    #[serde(default)]
    channel: String,
    #[serde(default)]
    review_type: String,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyContext {}

#[derive(Debug, Deserialize, Default, Clone)]
struct GuidedQuestion {
    question_id: String,
    question_text: String,
    requirement_id: String,
    cluster_id: String,
    #[serde(default)]
    required_document_kinds: Vec<String>,
    #[serde(default)]
    documentation_hint: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct StructuredHistory {
    #[serde(default)]
    diagnoses: Vec<ClinicalEvent>,
    #[serde(default)]
    procedures: Vec<ClinicalEvent>,
    #[serde(default)]
    medications: Vec<ClinicalEvent>,
    #[serde(default)]
    note_assertions: Vec<ClinicalEvent>,
}

#[derive(Debug, Deserialize, Default)]
struct MemberEvidence {
    #[serde(default)]
    structured_events: Vec<ClinicalEvent>,
    #[serde(default)]
    unstructured_documents: Vec<EvidenceDocument>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct ClinicalEvent {
    event_id: String,
    #[serde(default)]
    event_type: String,
    code: String,
    label: String,
    source: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct EvidenceDocument {
    document_id: String,
    kind: String,
    text: String,
    source: String,
    #[serde(default)]
    citation: Option<String>,
}

#[derive(Debug, Serialize)]
struct PolicySelectionCandidate {
    policy_id: String,
    title: String,
    score: f64,
    matched_terms: Vec<String>,
    selector_reasons: Vec<String>,
    selected: bool,
}

#[derive(Debug, Serialize)]
struct PolicySelectionResult {
    request_id: String,
    requested_service: String,
    selected_policy_ids: Vec<String>,
    ambiguous_policy_ids: Vec<String>,
    candidates: Vec<PolicySelectionCandidate>,
    selector_version: String,
}

#[derive(Debug, Clone)]
struct CandidateAssertion {
    cluster_id: String,
    confidence: f64,
    source_document_id: String,
    source_snippet: String,
    citation: Option<String>,
    matched_terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewedAssertion {
    assertion_id: String,
    cluster_id: String,
    status: String,
    trust_score: f64,
    source_document_id: String,
    source_snippet: String,
}

#[derive(Debug, Serialize, Clone)]
struct MatchedEvidence {
    kind: String,
    source: String,
    snippet: String,
}

#[derive(Debug, Serialize, Clone)]
struct QuestionResult {
    question_id: String,
    policy_id: String,
    requirement_id: String,
    question_text: String,
    status: String,
    documentation_status: String,
    missing_document_kinds: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matched_evidence: Vec<MatchedEvidence>,
    #[serde(skip_serializing_if = "String::is_empty")]
    reason: String,
}

#[derive(Debug, Serialize)]
struct FiredBit {
    bit: usize,
    bit_kind: String,
    policy_id: String,
    question_id: String,
    question_text: String,
}

#[derive(Debug, Serialize)]
struct ReviewSummary {
    route_status: String,
    review_summary: String,
}

#[derive(Debug, Serialize)]
struct ExplainOutput {
    ok: bool,
    artifact_id: String,
    request_id: String,
    selected_policy_ids: Vec<String>,
    ambiguous_policy_ids: Vec<String>,
    logic_bitmask: u64,
    documentation_bitmask: u64,
    bitmask: u64,
    route_status: String,
    documentation_complete: bool,
    missing_question_ids: Vec<String>,
    ambiguous_question_ids: Vec<String>,
    missing_documentation_count: usize,
    fired_bits: Vec<FiredBit>,
    question_explanations: Vec<QuestionResult>,
    selector_summary: SelectorSummary,
    review_summary: ReviewSummary,
}

#[derive(Debug, Serialize)]
struct SelectorSummary {
    selected_policy_ids: Vec<String>,
    ambiguous_policy_ids: Vec<String>,
    selector_version: String,
}

#[derive(Debug, Serialize)]
struct EvaluateOutput {
    ok: bool,
    artifact_id: String,
    request_id: String,
    selected_policy_ids: Vec<String>,
    ambiguous_policy_ids: Vec<String>,
    logic_bitmask: u64,
    documentation_bitmask: u64,
    bitmask: u64,
    route_status: String,
    documentation_complete: bool,
    missing_question_ids: Vec<String>,
    ambiguous_question_ids: Vec<String>,
    missing_documentation_count: usize,
    questions: Vec<CompactQuestionResult>,
}

#[derive(Debug, Serialize, Clone)]
struct CompactQuestionResult {
    question_id: String,
    policy_id: String,
    question_text: String,
    status: String,
    documentation_status: String,
    missing_document_kinds: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CounterfactualOutput {
    ok: bool,
    artifact_id: String,
    request_id: String,
    selected_policy_ids: Vec<String>,
    bitmask: u64,
    counterfactuals: Vec<Counterfactual>,
}

#[derive(Debug, Serialize)]
struct Counterfactual {
    bit: usize,
    bit_kind: String,
    policy_id: String,
    question_id: String,
    summary: String,
    recommended_action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    set_features: Vec<FeatureAction>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    required_document_kinds: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_document_kinds: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FeatureAction {
    feature: String,
    set_to: f64,
    reason: String,
}

struct Args {
    mode: String,
    input_path: Option<String>,
    as_json: bool,
    use_color: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    if args.mode == "describe" {
        let payload = serde_json::json!({
            "ok": true,
            "artifact_id": bundle().artifact_id,
            "artifact_name": bundle().artifact_id,
            "artifact_type": "corpus_runtime_pearl",
            "policy_count": bundle().policy_count,
            "build_info": {
                "runtime": "native_rust",
                "selector_version": "deterministic_policy_selector_v1",
                "bundle_format": "mkh_corpus_bundle_v1",
            },
            "modes": ["describe", "validate", "evaluate", "explain", "counterfactual", "debug"],
        });
        print_payload(&payload, args.as_json, args.use_color);
        return Ok(());
    }

    let mut request = load_request(args.input_path.as_deref())?;
    harmonize_request(&mut request);
    let evaluation = evaluate_request_against_corpus(&request);

    match args.mode.as_str() {
        "validate" => {
            let payload = serde_json::json!({
                "ok": true,
                "artifact_id": bundle().artifact_id,
                "request_id": request.request.request_id,
                "selected_policy_ids": evaluation.selector.selected_policy_ids,
                "ambiguous_policy_ids": evaluation.selector.ambiguous_policy_ids,
            });
            print_payload(&payload, args.as_json, args.use_color);
        }
        "evaluate" => {
            print_payload(
                &serde_json::to_value(evaluation.compact())?,
                args.as_json,
                args.use_color,
            );
        }
        "explain" => {
            print_payload(
                &serde_json::to_value(evaluation.explain())?,
                args.as_json,
                args.use_color,
            );
        }
        "counterfactual" => {
            print_payload(
                &serde_json::to_value(evaluation.counterfactuals())?,
                args.as_json,
                args.use_color,
            );
        }
        "debug" => {
            let payload = serde_json::json!({
                "ok": true,
                "artifact_id": bundle().artifact_id,
                "request_id": request.request.request_id,
                "selected_policy_ids": evaluation.selector.selected_policy_ids,
                "ambiguous_policy_ids": evaluation.selector.ambiguous_policy_ids,
                "logic_bitmask": evaluation.logic_bitmask,
                "documentation_bitmask": evaluation.documentation_bitmask,
                "bitmask": evaluation.logic_bitmask | evaluation.documentation_bitmask,
                "route_status": evaluation.route_status,
                "documentation_complete": evaluation.missing_documentation_count == 0,
                "missing_question_ids": evaluation.missing_question_ids,
                "ambiguous_question_ids": evaluation.ambiguous_question_ids,
                "missing_documentation_count": evaluation.missing_documentation_count,
                "questions": evaluation.questions,
                "selector": evaluation.selector,
            });
            print_payload(&payload, true, false);
        }
        _ => {
            let payload = serde_json::json!({
                "ok": false,
                "artifact_id": bundle().artifact_id,
                "error_code": "unknown_mode",
                "message": format!("unknown mode: {}", args.mode),
            });
            print_payload(&payload, true, false);
            std::process::exit(1);
        }
    }
    Ok(())
}

fn parse_args() -> Args {
    let mut mode = "describe".to_string();
    let mut input_path = None;
    let mut as_json = false;
    let mut force_color = false;
    let mut no_color = false;
    let argv: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    if let Some(first) = argv.first() {
        if !first.starts_with("--") {
            mode = first.clone();
            index = 1;
        }
    }
    while index < argv.len() {
        match argv[index].as_str() {
            "--input" => {
                if index + 1 < argv.len() {
                    input_path = Some(argv[index + 1].clone());
                    index += 1;
                }
            }
            "--json" => as_json = true,
            "--color" => force_color = true,
            "--no-color" => no_color = true,
            _ => {}
        }
        index += 1;
    }
    let use_color = !as_json
        && !no_color
        && (force_color || (std::io::IsTerminal::is_terminal(&std::io::stdout()) && env::var("NO_COLOR").is_err()));
    Args { mode, input_path, as_json, use_color }
}

fn load_request(path: Option<&str>) -> Result<HealthcarePolicyRequest, Box<dyn std::error::Error>> {
    let content = if let Some(path) = path {
        fs::read_to_string(path)?
    } else {
        return Err("missing --input <request.json>".into());
    };
    Ok(serde_json::from_str(&content)?)
}

fn harmonize_request(request: &mut HealthcarePolicyRequest) {
    if request.member_evidence.structured_events.is_empty() {
        if let Some(history) = &request.structured_history {
            request.member_evidence.structured_events = history
                .diagnoses
                .iter()
                .chain(history.procedures.iter())
                .chain(history.medications.iter())
                .chain(history.note_assertions.iter())
                .cloned()
                .collect();
        }
    }
    if request.member_evidence.unstructured_documents.is_empty() {
        request.member_evidence.unstructured_documents = request.clinical_documents.clone();
    }
}

struct CorpusEvaluation {
    selector: PolicySelectionResult,
    questions: Vec<QuestionResult>,
    route_status: String,
    logic_bitmask: u64,
    documentation_bitmask: u64,
    missing_question_ids: Vec<String>,
    ambiguous_question_ids: Vec<String>,
    missing_documentation_count: usize,
}

impl CorpusEvaluation {
    fn compact(&self) -> EvaluateOutput {
        EvaluateOutput {
            ok: true,
            artifact_id: bundle().artifact_id.clone(),
            request_id: self.selector.request_id.clone(),
            selected_policy_ids: self.selector.selected_policy_ids.clone(),
            ambiguous_policy_ids: self.selector.ambiguous_policy_ids.clone(),
            logic_bitmask: self.logic_bitmask,
            documentation_bitmask: self.documentation_bitmask,
            bitmask: self.logic_bitmask | self.documentation_bitmask,
            route_status: self.route_status.clone(),
            documentation_complete: self.missing_documentation_count == 0,
            missing_question_ids: self.missing_question_ids.clone(),
            ambiguous_question_ids: self.ambiguous_question_ids.clone(),
            missing_documentation_count: self.missing_documentation_count,
            questions: self.questions.iter().map(CompactQuestionResult::from).collect(),
        }
    }

    fn explain(&self) -> ExplainOutput {
        let mut fired_bits = Vec::new();
        for (index, question) in self.questions.iter().enumerate() {
            if self.logic_bitmask & (1u64 << index) != 0 {
                fired_bits.push(FiredBit {
                    bit: index,
                    bit_kind: "requirement".to_string(),
                    policy_id: question.policy_id.clone(),
                    question_id: question.question_id.clone(),
                    question_text: question.question_text.clone(),
                });
            }
        }
        let offset = self.questions.len();
        for (index, question) in self.questions.iter().enumerate() {
            let bit = offset + index;
            if self.documentation_bitmask & (1u64 << bit) != 0 {
                fired_bits.push(FiredBit {
                    bit,
                    bit_kind: "documentation".to_string(),
                    policy_id: question.policy_id.clone(),
                    question_id: question.question_id.clone(),
                    question_text: question.question_text.clone(),
                });
            }
        }
        ExplainOutput {
            ok: true,
            artifact_id: bundle().artifact_id.clone(),
            request_id: self.selector.request_id.clone(),
            selected_policy_ids: self.selector.selected_policy_ids.clone(),
            ambiguous_policy_ids: self.selector.ambiguous_policy_ids.clone(),
            logic_bitmask: self.logic_bitmask,
            documentation_bitmask: self.documentation_bitmask,
            bitmask: self.logic_bitmask | self.documentation_bitmask,
            route_status: self.route_status.clone(),
            documentation_complete: self.missing_documentation_count == 0,
            missing_question_ids: self.missing_question_ids.clone(),
            ambiguous_question_ids: self.ambiguous_question_ids.clone(),
            missing_documentation_count: self.missing_documentation_count,
            fired_bits,
            question_explanations: self.questions.clone(),
            selector_summary: SelectorSummary {
                selected_policy_ids: self.selector.selected_policy_ids.clone(),
                ambiguous_policy_ids: self.selector.ambiguous_policy_ids.clone(),
                selector_version: self.selector.selector_version.clone(),
            },
            review_summary: ReviewSummary {
                route_status: self.route_status.clone(),
                review_summary: "Guided intake completed. The packet organizes submitted clinical documents, maps candidate evidence to policy questions, and preserves final clinical determination for the reviewer.".to_string(),
            },
        }
    }

    fn counterfactuals(&self) -> CounterfactualOutput {
        let mut items = Vec::new();
        for (index, question) in self.questions.iter().enumerate() {
            if self.logic_bitmask & (1u64 << index) != 0 {
                let summary = human_requirement_counterfactual(&question.question_text);
                items.push(Counterfactual {
                    bit: index,
                    bit_kind: "requirement".to_string(),
                    policy_id: question.policy_id.clone(),
                    question_id: question.question_id.clone(),
                    summary: summary.clone(),
                    recommended_action: summary,
                    set_features: vec![FeatureAction {
                        feature: format!("requirement__{}__satisfied", question.requirement_id),
                        set_to: 1.0,
                        reason: format!("Set requirement__{}__satisfied to 1.0.", question.requirement_id),
                    }],
                    required_document_kinds: vec![],
                    missing_document_kinds: vec![],
                });
            }
        }
        let offset = self.questions.len();
        for (index, question) in self.questions.iter().enumerate() {
            let bit = offset + index;
            if self.documentation_bitmask & (1u64 << bit) != 0 {
                let summary = human_documentation_counterfactual(&question.missing_document_kinds);
                items.push(Counterfactual {
                    bit,
                    bit_kind: "documentation".to_string(),
                    policy_id: question.policy_id.clone(),
                    question_id: question.question_id.clone(),
                    summary: summary.clone(),
                    recommended_action: summary,
                    set_features: vec![],
                    required_document_kinds: vec![],
                    missing_document_kinds: question.missing_document_kinds.clone(),
                });
            }
        }
        CounterfactualOutput {
            ok: true,
            artifact_id: bundle().artifact_id.clone(),
            request_id: self.selector.request_id.clone(),
            selected_policy_ids: self.selector.selected_policy_ids.clone(),
            bitmask: self.logic_bitmask | self.documentation_bitmask,
            counterfactuals: items,
        }
    }
}

fn evaluate_request_against_corpus(request: &HealthcarePolicyRequest) -> CorpusEvaluation {
    let selector = select_applicable_policies(request, &bundle().policies);
    let selected_ids: HashSet<&str> = selector.selected_policy_ids.iter().map(String::as_str).collect();
    let mut selected_policies: Vec<&PolicySpec> = bundle()
        .policies
        .iter()
        .filter(|policy| selected_ids.contains(policy.policy_id.as_str()))
        .collect();
    selected_policies.sort_by_key(|policy| selector.selected_policy_ids.iter().position(|id| id == &policy.policy_id).unwrap_or(usize::MAX));

    let mut questions = Vec::new();
    let mut missing_question_ids = Vec::new();
    let mut ambiguous_question_ids = Vec::new();
    let mut logic_bitmask = 0u64;
    let mut documentation_bitmask = 0u64;
    let mut missing_documentation_count = 0usize;

    let all_docs = &request.member_evidence.unstructured_documents;
    let all_events = &request.member_evidence.structured_events;

    let total_requirements = selected_requirement_count(&selected_policies);
    let mut q_index = 1usize;
    for policy in &selected_policies {
        let guided = build_guided_questions(policy);
        let candidate_assertions = extract_candidate_assertions(policy, all_docs);
        let reviewed_assertions = review_candidate_assertions(policy, &candidate_assertions, all_events);
        for requirement in &policy.requirements {
            let guided_question = guided.iter().find(|item| item.requirement_id == requirement.requirement_id);
            let cluster = policy.clusters.iter().find(|cluster| cluster.cluster_id == requirement.cluster_id).unwrap();
            let structured_matches: Vec<ClinicalEvent> = all_events
                .iter()
                .filter(|event| cluster.codes.iter().any(|code| code.eq_ignore_ascii_case(&event.code)))
                .cloned()
                .collect();
            let cluster_reviewed: Vec<&ReviewedAssertion> = reviewed_assertions
                .iter()
                .filter(|item| item.cluster_id == requirement.cluster_id)
                .collect();
            let accepted: Vec<&ReviewedAssertion> = cluster_reviewed.iter().copied().filter(|item| item.status == "accepted").collect();
            let ambiguous: Vec<&ReviewedAssertion> = cluster_reviewed
                .iter()
                .copied()
                .filter(|item| item.status == "ambiguous" || item.status == "needs_human_review")
                .collect();

            let mut matched_evidence: Vec<MatchedEvidence> = structured_matches
                .iter()
                .map(|event| MatchedEvidence {
                    kind: event.event_type.clone(),
                    source: event.source.clone(),
                    snippet: event.label.clone(),
                })
                .collect();
            matched_evidence.extend(accepted.iter().map(|item| MatchedEvidence {
                kind: "reviewed_assertion".to_string(),
                source: item.source_document_id.clone(),
                snippet: item.source_snippet.clone(),
            }));
            if !ambiguous.is_empty() && matched_evidence.is_empty() {
                matched_evidence.extend(ambiguous.iter().map(|item| MatchedEvidence {
                    kind: "candidate_assertion".to_string(),
                    source: item.source_document_id.clone(),
                    snippet: item.source_snippet.clone(),
                }));
            }

            let required_document_kinds = guided_question
                .map(|g| g.required_document_kinds.clone())
                .unwrap_or_else(|| default_document_kinds_for_requirement(&requirement.kind));
            let available_kinds: HashSet<&str> = all_docs.iter().map(|doc| doc.kind.as_str()).collect();
            let missing_document_kinds: Vec<String> = required_document_kinds
                .iter()
                .filter(|kind| !available_kinds.contains(kind.as_str()))
                .cloned()
                .collect();
            let documentation_status = if !ambiguous.is_empty() {
                "ambiguous".to_string()
            } else if required_document_kinds.is_empty() || required_document_kinds.iter().any(|kind| available_kinds.contains(kind.as_str())) {
                "present".to_string()
            } else {
                "missing_required_documentation".to_string()
            };

            let (status, reason) = if !structured_matches.is_empty() || !accepted.is_empty() {
                ("found".to_string(), "Mapped structured history and/or accepted reviewed assertions to the guided policy question.".to_string())
            } else if !ambiguous.is_empty() {
                ambiguous_question_ids.push(format!("q{}", q_index));
                ("ambiguous".to_string(), "Only ambiguous or needs-review reviewed assertions were available for this guided policy question.".to_string())
            } else {
                missing_question_ids.push(format!("q{}", q_index));
                ("not_found".to_string(), "No structured history or accepted reviewed assertions matched the guided policy question.".to_string())
            };

            let question_text = guided_question
                .map(|g| g.question_text.clone())
                .unwrap_or_else(|| requirement.question_text.clone());
            let question = QuestionResult {
                question_id: format!("q{}", q_index),
                policy_id: policy.policy_id.clone(),
                requirement_id: requirement.requirement_id.clone(),
                question_text,
                status: status.clone(),
                documentation_status: documentation_status.clone(),
                missing_document_kinds: missing_document_kinds.clone(),
                matched_evidence,
                reason,
            };
            if status != "found" {
                logic_bitmask |= 1u64 << (q_index - 1);
            }
            if documentation_status == "missing_required_documentation" {
                documentation_bitmask |= 1u64 << (total_requirements + (q_index - 1));
                missing_documentation_count += 1;
            }
            questions.push(question);
            q_index += 1;
        }
    }

    let route_status = if questions.iter().any(|q| q.status == "ambiguous" || q.documentation_status == "ambiguous") {
        "needs_human_review".to_string()
    } else if missing_documentation_count > 0 {
        "missing_required_documentation".to_string()
    } else {
        "ready_for_clinical_review".to_string()
    };

    CorpusEvaluation {
        selector,
        questions,
        route_status,
        logic_bitmask,
        documentation_bitmask,
        missing_question_ids,
        ambiguous_question_ids,
        missing_documentation_count,
    }
}

fn selected_requirement_count(policies: &[&PolicySpec]) -> usize {
    policies.iter().map(|policy| policy.requirements.len()).sum()
}

fn select_applicable_policies(request: &HealthcarePolicyRequest, policies: &[PolicySpec]) -> PolicySelectionResult {
    let request_terms = request_terms(request);
    let request_phrase = request.request.requested_service.label.trim().to_lowercase();
    let evidence_terms = request_evidence_terms(request);
    let mut candidates = Vec::new();
    for policy in policies {
        let policy_terms = policy_terms(policy);
        let mut matched_terms: Vec<String> = request_terms.intersection(&policy_terms).cloned().collect();
        matched_terms.sort();
        let mut score = 0.0;
        let mut reasons = Vec::new();
        if !request_phrase.is_empty() && policy.title.to_lowercase().contains(&request_phrase) {
            score += 6.0;
            reasons.push("requested_service_phrase_in_title".to_string());
        }
        if !matched_terms.is_empty() {
            score += (matched_terms.len() as f64 * 2.0).min(6.0);
            reasons.push(format!("title_term_overlap:{}", matched_terms.iter().take(6).cloned().collect::<Vec<_>>().join(",")));
        }
        let mut supporting_terms: Vec<String> = evidence_terms.intersection(&policy_terms).cloned().collect();
        supporting_terms.sort();
        if !supporting_terms.is_empty() {
            score += (supporting_terms.len() as f64).min(3.0);
            reasons.push(format!("evidence_term_overlap:{}", supporting_terms.iter().take(6).cloned().collect::<Vec<_>>().join(",")));
        }
        if request.request.requested_service.kind == "drug"
            && (policy.policy_id.contains("medication") || policy.policy_id.contains("drug"))
        {
            score += 0.5;
            reasons.push("service_kind_matches_medication_policy_shape".to_string());
        }
        if request.request.requested_service.kind == "procedure" && policy.policy_id.contains("procedure") {
            score += 0.5;
            reasons.push("service_kind_matches_procedure_policy_shape".to_string());
        }
        if score <= 0.0 {
            continue;
        }
        let mut combined = matched_terms.clone();
        for term in supporting_terms {
            if !combined.contains(&term) {
                combined.push(term);
            }
        }
        candidates.push(PolicySelectionCandidate {
            policy_id: policy.policy_id.clone(),
            title: policy.title.clone(),
            score: (score * 100.0).round() / 100.0,
            matched_terms: combined,
            selector_reasons: reasons,
            selected: false,
        });
    }
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap().then_with(|| a.policy_id.cmp(&b.policy_id)));
    let mut selected_policy_ids = Vec::new();
    let mut ambiguous_policy_ids = Vec::new();
    if let Some(top) = candidates.first() {
        let dynamic_threshold = 2.0f64.max(top.score - 1.0);
        for candidate in &mut candidates {
            if candidate.score < dynamic_threshold || selected_policy_ids.len() >= 6 {
                break;
            }
            candidate.selected = true;
            selected_policy_ids.push(candidate.policy_id.clone());
        }
        for candidate in &candidates {
            if !candidate.selected && candidate.score >= dynamic_threshold - 0.5 {
                ambiguous_policy_ids.push(candidate.policy_id.clone());
            }
        }
    }
    PolicySelectionResult {
        request_id: request.request.request_id.clone(),
        requested_service: request.request.requested_service.label.clone(),
        selected_policy_ids,
        ambiguous_policy_ids,
        candidates,
        selector_version: "deterministic_policy_selector_v1".to_string(),
    }
}

fn request_terms(request: &HealthcarePolicyRequest) -> HashSet<String> {
    let mut terms = HashSet::new();
    terms.extend(tokenize(&request.request.requested_service.label));
    terms.extend(tokenize(&request.request.requested_service.code));
    if let Some(product) = &request.request.product {
        terms.extend(tokenize(product));
    }
    if let Some(lob) = &request.request.line_of_business {
        terms.extend(tokenize(lob));
    }
    terms
}

fn request_evidence_terms(request: &HealthcarePolicyRequest) -> HashSet<String> {
    let mut terms = HashSet::new();
    for event in &request.member_evidence.structured_events {
        terms.extend(tokenize(&event.label));
        terms.extend(tokenize(&event.code));
    }
    terms
}

fn policy_terms(policy: &PolicySpec) -> HashSet<String> {
    let mut terms = HashSet::new();
    terms.extend(tokenize(&policy.policy_id));
    terms.extend(tokenize(&policy.title));
    for source in &policy.sources {
        terms.extend(tokenize(&source.title));
        if let Some(section_note) = &source.section_note {
            terms.extend(tokenize(section_note));
        }
    }
    terms
}

fn tokenize(value: &str) -> HashSet<String> {
    let stopwords: HashSet<&str> = [
        "a","an","and","auth","authorization","benefit","bluecrossma","bcbsma","clinical","documentation","for","history","in","medical","of","or","policy","prn","prereq","prior","required","requirement","review","step","therapy","the","to","with"
    ].into_iter().collect();
    let mut out = HashSet::new();
    let mut current = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            if current.len() > 2 && !stopwords.contains(current.as_str()) && !current.chars().all(|c| c.is_ascii_digit()) {
                out.insert(current.clone());
            }
            current.clear();
        }
    }
    if !current.is_empty() && current.len() > 2 && !stopwords.contains(current.as_str()) && !current.chars().all(|c| c.is_ascii_digit()) {
        out.insert(current);
    }
    out
}

fn build_guided_questions(policy: &PolicySpec) -> Vec<GuidedQuestion> {
    policy
        .requirements
        .iter()
        .enumerate()
        .map(|(index, requirement)| GuidedQuestion {
            question_id: format!("gq{}", index + 1),
            question_text: question_text_for_requirement(requirement, policy.clusters.iter().find(|c| c.cluster_id == requirement.cluster_id)),
            requirement_id: requirement.requirement_id.clone(),
            cluster_id: requirement.cluster_id.clone(),
            required_document_kinds: default_document_kinds_for_requirement(&requirement.kind),
            documentation_hint: Some(requirement.evidence_needed.clone()),
        })
        .collect()
}

fn question_text_for_requirement(requirement: &RequirementSpec, cluster: Option<&ClusterSpec>) -> String {
    let key = format!(
        "{} {} {}",
        requirement.cluster_id,
        cluster.map(|c| c.label.as_str()).unwrap_or(""),
        requirement.evidence_needed
    )
    .to_lowercase();
    if key.contains("trial_of_formulary_alternatives") || key.contains("formulary alternative") {
        return "Did we find evidence of a trial of formulary alternatives?".to_string();
    }
    if key.contains("prior_trial_of_step_therapy_medication") || key.contains("prior step-therapy medication trial") {
        return "Did we find evidence of a prior step-therapy medication trial?".to_string();
    }
    if key.contains("failed_conservative_therapy") {
        return "Did we find evidence of failed conservative therapy?".to_string();
    }
    if key.contains("prior_physical_therapy") || key.contains("physical therapy") {
        return "Did we find evidence of prior physical therapy?".to_string();
    }
    if key.contains("supporting documentation") || key.contains("documentation") {
        return "Did we find the required supporting documentation?".to_string();
    }
    if key.contains("diagnosis") {
        return "Did we find evidence of a qualifying diagnosis?".to_string();
    }
    normalize_question_text(&requirement.question_text)
}

fn normalize_question_text(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let remainder = stripped[end + 1..].trim();
            if !remainder.is_empty() {
                return remainder.to_string();
            }
        }
    }
    trimmed.to_string()
}

fn default_document_kinds_for_requirement(kind: &str) -> Vec<String> {
    match kind {
        "diagnosis_present" => vec!["prior_auth_form", "office_note", "problem_list"],
        "procedure_completed" => vec!["procedure_history", "office_note", "therapy_report"],
        "medication_trial" => vec!["medication_history", "office_note", "pharmacy_history"],
        "note_assertion_present" => vec!["office_note", "clinical_attachment"],
        _ => vec!["office_note"],
    }
    .into_iter()
    .map(String::from)
    .collect()
}

fn extract_candidate_assertions(policy: &PolicySpec, documents: &[EvidenceDocument]) -> Vec<CandidateAssertion> {
    let mut out = Vec::new();
    for cluster in &policy.clusters {
        let alias_terms = filter_alias_terms(&cluster.aliases);
        for document in documents {
            if let Some((matched_terms, snippet, confidence)) = find_cluster_match(&document.text, &alias_terms, &cluster.codes) {
                out.push(CandidateAssertion {
                    cluster_id: cluster.cluster_id.clone(),
                    confidence,
                    source_document_id: document.document_id.clone(),
                    source_snippet: snippet,
                    citation: document.citation.clone(),
                    matched_terms,
                });
            }
        }
    }
    out
}

fn review_candidate_assertions(policy: &PolicySpec, assertions: &[CandidateAssertion], structured_events: &[ClinicalEvent]) -> Vec<ReviewedAssertion> {
    let structured_set: HashSet<String> = structured_events.iter().map(|e| e.code.trim().to_ascii_uppercase()).collect();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for assertion in assertions {
        *counts.entry(assertion.cluster_id.as_str()).or_insert(0) += 1;
    }
    let mut out = Vec::new();
    for assertion in assertions {
        let cluster = policy.clusters.iter().find(|c| c.cluster_id == assertion.cluster_id).unwrap();
        let mut trust = assertion.confidence;
        if assertion.citation.is_some() {
            trust += 0.1;
        }
        if counts.get(assertion.cluster_id.as_str()).copied().unwrap_or(0) > 1 {
            trust += 0.15;
        }
        if cluster.codes.iter().any(|code| structured_set.contains(&code.trim().to_ascii_uppercase())) {
            trust += 0.2;
        }
        if cluster.codes.iter().take(2).any(|code| assertion.source_snippet.to_ascii_uppercase().contains(&code.to_ascii_uppercase())) {
            trust += 0.1;
        }
        if assertion.matched_terms.len() > 1 {
            trust += 0.05;
        }
        trust = trust.min(0.99);
        let status = if trust >= 0.85 {
            "accepted"
        } else if trust >= 0.65 {
            "ambiguous"
        } else {
            "needs_human_review"
        };
        out.push(ReviewedAssertion {
            assertion_id: format!("{}__{}", assertion.source_document_id, assertion.cluster_id),
            cluster_id: assertion.cluster_id.clone(),
            status: status.to_string(),
            trust_score: trust,
            source_document_id: assertion.source_document_id.clone(),
            source_snippet: assertion.source_snippet.clone(),
        });
    }
    out
}

fn filter_alias_terms(alias_terms: &[String]) -> Vec<String> {
    let blocked: HashSet<&str> = [
        "step therapy","managed care","ppo/epo","medex with rx plans","medex with rx plans*","indemnity","ndemnity",
        "a clinician's or physician's office","a clinician’s or physician’s office","a home health care provider","a home infusion therapy provider",
        "outpatient hospital and dialysis settings","surgical day care","policy does not apply to"
    ].into_iter().collect();
    let mut out = Vec::new();
    for alias in alias_terms {
        let normalized = alias.split_whitespace().collect::<Vec<_>>().join(" ");
        let lowered = normalized.to_lowercase();
        let token_count = tokenize(&lowered).len();
        if lowered.is_empty() || blocked.contains(lowered.as_str()) {
            continue;
        }
        if token_count < 2 && !normalized.chars().any(|c| c.is_ascii_digit()) {
            continue;
        }
        if normalized.len() < 8 {
            continue;
        }
        out.push(normalized);
    }
    out
}

fn find_cluster_match(text: &str, alias_terms: &[String], code_terms: &[String]) -> Option<(Vec<String>, String, f64)> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let lowered = normalized.to_lowercase();
    let mut matched_terms = Vec::new();
    for term in code_terms {
        if !term.is_empty() && lowered.contains(&term.to_lowercase()) {
            matched_terms.push(term.clone());
        }
    }
    let ambiguity_terms = ["possible","possibly","suspected","suggests","unclear","unconfirmed","not confirmed","incomplete","pending","may have","might have"];
    let evidence_terms = ["history","trial","tried","failed","failure","contraindication","documented","diagnosed","diagnosis","completed","received","prior","previous","claim","claims","medication","assessment","office note","clinical note","lab","pharmacy"];
    for alias in alias_terms {
        let alias_lower = alias.to_lowercase();
        let mut search_from = 0;
        while let Some(found) = lowered[search_from..].find(&alias_lower) {
            let alias_index = search_from + found;
            let window_start = alias_index.saturating_sub(120);
            let window_end = (alias_index + alias_lower.len() + 120).min(lowered.len());
            let window = &lowered[window_start..window_end];
            if ambiguity_terms.iter().any(|term| window.contains(term)) {
                search_from = alias_index + alias_lower.len();
                continue;
            }
            if evidence_terms.iter().any(|term| window.contains(term)) {
                matched_terms.push(alias.clone());
                break;
            }
            search_from = alias_index + alias_lower.len();
        }
    }
    if matched_terms.is_empty() {
        return None;
    }
    let earliest = matched_terms
        .iter()
        .filter_map(|term| lowered.find(&term.to_lowercase()))
        .min()
        .unwrap_or(0);
    let start = earliest.saturating_sub(80);
    let end = (earliest + 180).min(normalized.len());
    let snippet = normalized[start..end].trim().to_string();
    let mut confidence: f64 = 0.72;
    if matched_terms.iter().any(|term| code_terms.contains(term)) {
        confidence += 0.15;
    }
    if matched_terms.len() > 1 {
        confidence += 0.05;
    }
    if ambiguity_terms.iter().any(|term| lowered.contains(term)) {
        confidence -= 0.1;
    }
    if ["completed","tried","history of","diagnosed with","documented"].iter().any(|term| lowered.contains(term)) {
        confidence += 0.05;
    }
    Some((matched_terms, snippet, confidence.min(0.95)))
}
fn human_requirement_counterfactual(question_text: &str) -> String {
    let key = question_text.to_lowercase();
    if key.contains("formulary alternatives") {
        return "Provide evidence of a trial of formulary alternatives.".to_string();
    }
    if key.contains("step-therapy medication trial") {
        return "Provide evidence of a prior step-therapy medication trial.".to_string();
    }
    if key.contains("failed conservative therapy") {
        return "Provide evidence that conservative therapy was tried and failed.".to_string();
    }
    if key.contains("physical therapy") {
        return "Provide evidence of prior physical therapy.".to_string();
    }
    if key.contains("supporting documentation") {
        return "Provide the required supporting documentation.".to_string();
    }
    if key.contains("diagnosis") {
        return "Provide evidence of the qualifying diagnosis.".to_string();
    }
    "Provide evidence needed to satisfy this policy question.".to_string()
}

fn human_documentation_counterfactual(missing_document_kinds: &[String]) -> String {
    if missing_document_kinds.is_empty() {
        return "Provide one of the required supporting document types.".to_string();
    }
    let joined = missing_document_kinds.iter().map(|item| item.replace('_', " ")).collect::<Vec<_>>().join(", ");
    format!("Provide at least one of the missing document types: {}.", joined)
}

fn print_payload(payload: &Value, as_json: bool, use_color: bool) {
    if as_json {
        println!("{}", serde_json::to_string_pretty(payload).unwrap());
    } else {
        println!("{}", render_text(payload, use_color));
    }
}

fn render_text(payload: &Value, use_color: bool) -> String {
    let artifact = payload.get("artifact_id").and_then(Value::as_str).unwrap_or("unknown");
    if payload.get("modes").is_some() {
        let mut out = vec![style(&format!("Artifact: {}", artifact), Some("cyan"), true, use_color)];
        if let Some(policy_count) = payload.get("policy_count").and_then(Value::as_u64) {
            out.push(format!("Policy count: {}", policy_count));
        }
        if let Some(modes) = payload.get("modes").and_then(Value::as_array) {
            let joined = modes.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ");
            out.push(format!("Modes: {}", joined));
        }
        if let Some(build_info) = payload.get("build_info").and_then(Value::as_object) {
            if let Some(runtime) = build_info.get("runtime").and_then(Value::as_str) {
                out.push(format!("Runtime: {}", runtime));
            }
            if let Some(selector_version) = build_info.get("selector_version").and_then(Value::as_str) {
                out.push(format!("Selector: {}", selector_version));
            }
        }
        return out.join("\n");
    }
    let mut out = vec![
        style(&format!("Artifact: {}", artifact), Some("cyan"), true, use_color),
        format!("Request: {}", payload.get("request_id").and_then(Value::as_str).unwrap_or("n/a")),
        String::new(),
    ];
    if let Some(selected) = payload.get("selected_policy_ids").and_then(Value::as_array) {
        out.push(style("Selected policies", Some("blue"), true, use_color));
        for item in selected {
            if let Some(value) = item.as_str() {
                out.push(format!("  - {}", value));
            }
        }
        out.push(String::new());
    }
    if let Some(route) = payload.get("route_status").and_then(Value::as_str) {
        let route_color = if route == "ready_for_clinical_review" { Some("green") } else { Some("yellow") };
        out.push(format!("Route status: {}", style(route, route_color, true, use_color)));
    }
    for key in ["logic_bitmask", "documentation_bitmask", "bitmask"] {
        if let Some(value) = payload.get(key).and_then(Value::as_u64) {
            let label = match key {
                "logic_bitmask" => "Logic bitmask",
                "documentation_bitmask" => "Documentation bitmask",
                _ => "Combined bitmask",
            };
            out.push(format!("{}: {}", label, value));
        }
    }
    out.push(String::new());
    if let Some(questions) = payload.get("question_explanations").or_else(|| payload.get("questions")).and_then(Value::as_array) {
        out.push(style("Questions", Some("blue"), true, use_color));
        for question in questions {
            let status = question.get("status").and_then(Value::as_str).unwrap_or("unknown").to_uppercase();
            let status_color = match status.as_str() {
                "FOUND" => Some("green"),
                "NOT_FOUND" => Some("red"),
                "AMBIGUOUS" => Some("yellow"),
                _ => None,
            };
            let docs = question.get("documentation_status").and_then(Value::as_str).unwrap_or("");
            let question_text = question.get("question_text").and_then(Value::as_str).unwrap_or("unknown question");
            let docs_suffix = if docs.is_empty() { String::new() } else { format!(" (docs: {})", docs) };
            out.push(format!("  - {}: {}{}", style(&status, status_color, true, use_color), question_text, docs_suffix));
            if let Some(matched) = question.get("matched_evidence").and_then(Value::as_array) {
                for evidence in matched.iter().take(2) {
                    let kind = evidence.get("kind").and_then(Value::as_str).unwrap_or("evidence");
                    let source = evidence.get("source").and_then(Value::as_str).unwrap_or("unknown");
                    let mut snippet = evidence.get("snippet").and_then(Value::as_str).unwrap_or("").replace('\n', " ");
                    if snippet.len() > 140 {
                        snippet.truncate(137);
                        snippet.push_str("...");
                    }
                    out.push(format!("    {}: [{} via {}] {}", style("Evidence", Some("magenta"), true, use_color), kind, source, snippet));
                }
            }
            if let Some(reason) = question.get("reason").and_then(Value::as_str) {
                if !reason.is_empty() {
                    out.push(format!("    {}: {}", style("Why", Some("magenta"), true, use_color), reason));
                }
            }
            if let Some(missing) = question.get("missing_document_kinds").and_then(Value::as_array) {
                if docs == "missing_required_documentation" && !missing.is_empty() {
                    let joined = missing.iter().filter_map(Value::as_str).map(|s| s.replace('_', " ")).collect::<Vec<_>>().join(", ");
                    out.push(format!("    {}: {}", style("Missing docs", Some("yellow"), true, use_color), joined));
                }
            }
        }
        out.push(String::new());
    }
    if let Some(fired) = payload.get("fired_bits").and_then(Value::as_array) {
        if !fired.is_empty() {
            out.push(style("Fired bits", Some("blue"), true, use_color));
            for bit in fired {
                out.push(format!(
                    "  - bit {} {}: {}",
                    bit.get("bit").and_then(Value::as_u64).unwrap_or(0),
                    bit.get("bit_kind").and_then(Value::as_str).unwrap_or("unknown"),
                    bit.get("question_text").and_then(Value::as_str).unwrap_or("unknown"),
                ));
            }
            out.push(String::new());
        }
    }
    if let Some(counterfactuals) = payload.get("counterfactuals").and_then(Value::as_array) {
        if !counterfactuals.is_empty() {
            out.push(style("Counterfactuals", Some("blue"), true, use_color));
            for item in counterfactuals {
                out.push(format!("  - {}", item.get("summary").and_then(Value::as_str).unwrap_or("")));
            }
            out.push(String::new());
        }
    }
    if let Some(review) = payload.get("review_summary").and_then(Value::as_object) {
        if let Some(summary) = review.get("review_summary").and_then(Value::as_str) {
            out.push(style("Review summary", Some("blue"), true, use_color));
            out.push(summary.to_string());
        }
    }
    out.join("\n")
}

fn style(text: &str, color: Option<&str>, bold: bool, enabled: bool) -> String {
    if !enabled {
        return text.to_string();
    }
    let mut codes = Vec::new();
    if bold {
        codes.push("1");
    }
    if let Some(color) = color {
        codes.push(match color {
            "red" => "31",
            "green" => "32",
            "yellow" => "33",
            "blue" => "34",
            "magenta" => "35",
            "cyan" => "36",
            _ => "",
        });
    }
    let joined = codes.into_iter().filter(|item| !item.is_empty()).collect::<Vec<_>>().join(";");
    if joined.is_empty() {
        text.to_string()
    } else {
        format!("\x1b[{}m{}\x1b[0m", joined, text)
    }
}

impl From<&QuestionResult> for CompactQuestionResult {
    fn from(value: &QuestionResult) -> Self {
        Self {
            question_id: value.question_id.clone(),
            policy_id: value.policy_id.clone(),
            question_text: value.question_text.clone(),
            status: value.status.clone(),
            documentation_status: value.documentation_status.clone(),
            missing_document_kinds: value.missing_document_kinds.clone(),
        }
    }
}
