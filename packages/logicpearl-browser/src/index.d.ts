export type RuleMaskJson = number | number[] | string;

export interface FeatureExplanationV1 {
  feature_id: string;
  feature_label: string | null;
  source_id: string | null;
  source_anchor: string | null;
  state_label: string | null;
  state_message: string | null;
  counterfactual_hint: string | null;
  [key: string]: unknown;
}

export interface GateRuleExplanationV1 {
  id: string;
  bit: number;
  label: string | null;
  message: string | null;
  severity: string | null;
  counterfactual_hint: string | null;
  features?: FeatureExplanationV1[];
  [key: string]: unknown;
}

export interface ActionRuleExplanationV1 extends GateRuleExplanationV1 {
  action: string;
  priority: number;
}

export interface GateResultV1 {
  schema_version: 'logicpearl.gate_result.v1';
  engine_version: string;
  artifact_id: string;
  artifact_hash: string;
  policy_id: string;
  gate_id: string;
  decision_kind: 'gate';
  allow: boolean;
  bitmask: RuleMaskJson;
  defaulted: boolean;
  ambiguity: string | null;
  matched_rules: GateRuleExplanationV1[];
  [key: string]: unknown;
}

export interface ActionResultV1 {
  schema_version: 'logicpearl.action_result.v1';
  engine_version: string;
  artifact_id: string;
  artifact_hash: string;
  policy_id: string;
  action_policy_id: string;
  decision_kind: 'action';
  action: string;
  default_action?: string;
  no_match_action?: string | null;
  bitmask: RuleMaskJson;
  defaulted: boolean;
  no_match?: boolean;
  selected_rules: ActionRuleExplanationV1[];
  matched_rules: ActionRuleExplanationV1[];
  candidate_actions: string[];
  ambiguity: string | null;
  [key: string]: unknown;
}

export interface PipelineStageResultV1 {
  id: string;
  kind: 'pearl' | 'observer_plugin' | 'trace_source_plugin' | 'enricher_plugin' | 'verify_plugin';
  ok: boolean;
  skipped: boolean;
  exports: Record<string, unknown>;
  raw_result: unknown;
  [key: string]: unknown;
}

export interface PipelineResultV1 {
  schema_version: 'logicpearl.pipeline_result.v1';
  engine_version: string;
  artifact_id: string;
  artifact_hash: string;
  decision_kind: 'pipeline';
  pipeline_id: string;
  ok: boolean;
  output: Record<string, unknown>;
  stages: PipelineStageResultV1[];
  [key: string]: unknown;
}

export interface ArtifactErrorV1 {
  schema_version: 'logicpearl.artifact_error.v1';
  engine_version: string;
  artifact_id?: string;
  artifact_hash?: string;
  error_code: string;
  message: string;
  details?: unknown;
  [key: string]: unknown;
}

export type RuntimeResultV1 = GateResultV1 | ActionResultV1 | PipelineResultV1 | ArtifactErrorV1;

export interface ArtifactManifestFilesV1 {
  ir: string;
  build_report?: string;
  feature_dictionary?: string;
  wasm?: string;
  wasm_metadata?: string;
  native?: string;
  action_report?: string;
  [key: string]: unknown;
}

export interface ArtifactManifestV1 {
  schema_version: 'logicpearl.artifact_manifest.v1';
  artifact_id: string;
  artifact_kind: 'gate' | 'action' | 'pipeline';
  engine_version: string;
  ir_version: string;
  created_at: string;
  artifact_hash: string;
  files: ArtifactManifestFilesV1;
  input_schema_hash?: string;
  feature_dictionary_hash?: string;
  build_options_hash?: string;
  file_hashes?: Record<string, string>;
  bundle_hash?: string;
  [key: string]: unknown;
}

export interface BrowserRuleMetadata {
  id: string;
  bit: number;
  action?: string;
  priority?: number;
  label?: string | null;
  message?: string | null;
  severity?: string | null;
  counterfactual_hint?: string | null;
  features?: FeatureExplanationV1[];
  [key: string]: unknown;
}

export interface BrowserGateEvaluation {
  schemaVersion: 'logicpearl.gate_result.v1';
  engineVersion: string | null;
  artifactHash: string | null;
  decisionKind: 'gate';
  artifactId: string;
  policyId: string;
  gateId: string;
  allow: boolean;
  defaulted: boolean;
  ambiguity: string | null;
  bitmask: bigint;
  firedRuleIds: string[];
  firedRules: BrowserRuleMetadata[];
  primaryReason: BrowserRuleMetadata | null;
  counterfactualHints: string[];
}

export interface BrowserActionEvaluation {
  schemaVersion: 'logicpearl.action_result.v1';
  engineVersion: string | null;
  artifactHash: string | null;
  decisionKind: 'action';
  artifactId: string;
  policyId: string;
  actionPolicyId: string;
  action: string;
  defaultAction: string;
  noMatchAction: string | null;
  defaulted: boolean;
  noMatch: boolean;
  ambiguity: string | null;
  bitmask: bigint;
  matchedRuleIds: string[];
  matchedRules: BrowserRuleMetadata[];
  selectedRules: BrowserRuleMetadata[];
  candidateActions: string[];
  primaryReason: BrowserRuleMetadata | null;
  counterfactualHints: string[];
}

export type BrowserEvaluation = BrowserGateEvaluation | BrowserActionEvaluation;

export interface LogicPearlBrowserArtifact {
  inspect(): Record<string, unknown>;
  rules(): BrowserRuleMetadata[];
  evaluate(input: Record<string, unknown>): BrowserEvaluation;
  evaluateBatch(inputs: Array<Record<string, unknown>>): BrowserEvaluation[];
  evaluateJson(input: Record<string, unknown>): GateResultV1 | ActionResultV1;
  evaluateJsonBatch(inputs: Array<Record<string, unknown>>): Array<GateResultV1 | ActionResultV1>;
}

export interface LoadArtifactOptions {
  fetchImpl?: (url: string) => Promise<{
    ok?: boolean;
    status?: number | string;
    json?: () => Promise<unknown>;
    arrayBuffer?: () => Promise<ArrayBuffer>;
  }>;
  instantiateWasm?: (bytes: ArrayBuffer) => Promise<{ exports: Record<string, unknown> }>;
}

export interface BrowserArtifactBundle {
  manifest: ArtifactManifestV1;
  wasmModule: ArrayBuffer;
  wasmMetadata: Record<string, unknown>;
  artifactBaseUrl?: string | null;
  manifestUrl?: string | null;
}

export function loadArtifact(reference: string, options?: LoadArtifactOptions): Promise<LogicPearlBrowserArtifact>;
export function loadArtifactFromBundle(bundle: BrowserArtifactBundle, options?: Pick<LoadArtifactOptions, 'instantiateWasm'>): Promise<LogicPearlBrowserArtifact>;
export function normalizeArtifactReference(reference: string): { manifestUrl: string; artifactBaseUrl: string };
export function encodeFeatureSlots(input: Record<string, unknown>, metadata: Record<string, unknown>): Float64Array;
export function decodeFiredRules(bitmask: bigint, rules: BrowserRuleMetadata[]): BrowserRuleMetadata[];
