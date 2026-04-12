# LogicPearl Terminology

This file defines the core LogicPearl vocabulary in plain language.

If the README gives you the thesis, this file gives you the nouns.

The short version:
- raw messy input lives at the edge
- observers turn that input into normalized features or reviewed assertions
- pearls run deterministic logic over that normalized view
- AI is optional, but extremely useful in the messy parts of the system

LogicPearl does not require AI.

You can build and run pearls with deterministic observers only.

But AI fits naturally in this model:
- generating training traces
- synthesizing candidate trace examples from an English policy or behavior description
- synthesizing observers
- extracting candidate assertions from messy evidence
- calling pearls as deterministic tools inside larger agent workflows
- serving directly as observers when the input is messy language, documents, or ambiguous real-world evidence

That division matters:
- AI handles ambiguity
- observers normalize the world
- pearls keep the core exact
- AI systems can consult pearls when they need exact logic, policy checks, or deterministic knowledge instead of improvising

Use these terms consistently in docs, demos, and architecture notes.

## The Shape In One View

```text
raw input -> observer / adapter -> reviewed assertions or features -> pearl -> deterministic result
```

An observer is the translation layer between messy reality and deterministic logic.

It can be:
- a simple deterministic adapter
- a parser or classifier
- a domain-specific extraction pipeline
- an LLM or other model acting as an observer over freeform input

The point of the observer is not to make the final decision.
The point is to turn messy input into a normalized form the pearl can evaluate exactly.

The tables below break that model into concrete terms.

## The Pipeline (what runs once at setup time)

| Term | Definition | When it runs |
|---|---|---|
| **Trace Synthesis** | Generating labeled examples of correct (allowed) and incorrect (denied) decisions. Traces can come from historical data, hand-written archetypes, a declarative generator, or an LLM translating an English policy into reviewed examples. | Setup |
| **Rule Discovery** | Analyzing traces to find compact rules that reproduce a bounded behavior slice. Discovery can use greedy selection plus solver-backed exact selection or conjunction recovery. No LLM is involved in the deterministic runtime. | Setup |
| **Verification / Conformance** | Checking a pearl against its stated evidence: training traces, held-out traces, runtime parity cases, or an explicit formal spec. Stronger formal claims require an explicit spec or verification workflow, and artifact metadata should state that scope. | Setup |
| **Gate Compilation** | Compiling rules into a stateless, deterministic bitmask evaluator. Can target Rust-native execution or WASM. | Setup |

## Runtime (what runs on each request)

| Term | Definition | When it runs |
|---|---|---|
| **Observers** | Components that translate raw input into normalized features, evidence, or assertions at runtime. In content safety: classifiers. In RBAC: simple data transformations. In claims: domain adapters that turn raw claim lines, notes, or documents into observable facts. The pearl does not care where the normalized inputs came from; it only evaluates them deterministically. | Every request (or cached per session) |
| **AI-Assisted Observer** | An observer/adapter that uses an LLM or other probabilistic model to read freeform artifacts such as notes, attachments, OCR text, or conversations and emit candidate evidence assertions or normalized features. A model can itself be an observer. Its output is advisory until reviewed, filtered, corroborated, or otherwise trusted. | Every request (or cached per session) |
| **Candidate Assertion** | A provenance-carrying claim emitted by an observer from messy evidence. Example: “prior physical therapy found in note-17.” Candidate assertions are not final truth and should not directly decide a consequential outcome. | Every request |
| **Reviewed Assertion** | A candidate assertion after deterministic filtering, confidence gating, corroboration, or human review. Reviewed assertions are the trusted observer outputs that may feed feature extraction or direct policy-question evaluation. | Every request |
| **Intake Bundle** | The full inbound request packet for a consequential workflow: request metadata, submission channel, structured history, uploaded documents, guided questions, and policy context. This is the realistic runtime input shape for prior auth / UM workflows. | Every request |
| **Guided Question** | A fixed documentation or policy question presented during intake or review. Guided questions are the human-facing prompts that LogicPearl maps to requirement IDs and deterministic cluster checks. | Every request |
| **Feature Extraction** | The process observers perform — turning raw input into a flat dict of `{feature_name: float}` or other typed gate-ready values. Same contract at training time and runtime, but different data sources may supply the raw inputs. | Every request |
| **Gate Evaluation** | Checking the feature dict against compiled rules. Returns a bitmask where each bit = one rule. The runtime path is intended to be side-effect-free and deterministic. | Every request |

## Pearl And Gate Concepts

| Term | Definition |
|---|---|
| **Pearl** | A compiled deployable policy artifact. A pearl is the runtime-ready form of discovered and/or layered policy logic. Internally this may still be represented as Gate IR plus compiled runtime targets. |
| **String Of Pearls** | An ordered composition of multiple pearls evaluated together. Use this when policy is layered or staged across multiple deterministic artifacts. |
| **Pipeline** | The executable artifact that wires a string of pearls together. In public product surfaces, the composition artifact should be a `pipeline.json` that maps stage inputs, outputs, and conditions explicitly. |
| **Bitmask** | An integer where each bit position represents one invariant rule. Bit=0 means the rule passed, bit=1 means it failed. `bitmask == 0` means all rules passed (ALLOWED). Any set bit means DENIED. |
| **Invariant / Rule** | A predicate or conjunction of conditions, such as `feature1 > threshold1 AND feature2 <= threshold2`. Rules can be discovered from traces or layered from maintained/pinned rule files. Each rule occupies one bit in the bitmask. |
| **Condition** | A single threshold check: `feature_name operator threshold`. Operators: `>`, `>=`, `<`, `<=`, `==`, `!=`, `in`, or `not_in`, depending on the IR/runtime layer. |
| **Counterfactual** | For a denied verdict, the minimum change to the input that would flip the decision. "Change education from 11 to 13 to allow." |
| **Correctness Scope** | The evidence boundary for a pearl's current claim, such as training parity against a trace file, held-out benchmark scoring, runtime parity against an existing system, or solver verification against a formal spec. |
| **Training Parity** | The fraction of supplied decision traces reproduced by the emitted pearl. High training parity is useful evidence, but it is not a universal proof of the real-world policy. |
| **Soundness** | A rule is sound if it holds for 100% of allowed training traces — it never falsely denies an allowed case. |
| **Usefulness** | A rule is useful if it fires for at least some denied training traces — it actually catches denied cases. |
| **Denial Path** | In tree-style discovery, a root-to-leaf path where the leaf predicts `denied`. More generally, this is one recoverable reason a trace should deny. |

## Claims Audit Terms

| Term | Definition |
|---|---|
| **Primary Rule** | The rule exported as the official or top-level explanation for a denied case. In sequential or precedence-ordered engines, only one rule may be primary even if multiple rules fired. |
| **Latent Rule** | A rule that actually fired for a case internally, even if it was not exported as the primary label. In the claims audit demo, latent rule counts come from `all_rule_ids`, not just `primary_rule_id`. |
| **Shadowing** | A rule is shadowed when it fires internally but is hidden by an earlier or broader rule in the exported label. Shadowing is a data-labeling problem, not necessarily a discovery failure. |

## Gate Variants

| Term | Definition |
|---|---|
| **Binary Gate** | Standard gate: returns ALLOW or DENY. Each rule has one threshold or one denial predicate. |
| **Three-Zone Gate** | Extended gate: returns ALLOW, DENY, or ESCALATE. Each rule has a confidence zone — clearly passing, clearly failing, or ambiguous. Ambiguous cases are routed to a secondary evaluation path. |
| **Cascading Gates** | Multiple domain-specific gates combined via bitwise OR or another explicit composition rule. Each gate is independently discoverable and deployable. |
| **Pearl Bundle** | A package containing one or more pearls plus supporting manifests, provenance, or deployment metadata. Use this for packaging, not for evaluation semantics. |

## Discovery Strategies

| Term | Definition |
|---|---|
| **Sequential Covering** | The V2 pipeline's default: fit a tree, extract the best denial rule, remove covered cases, repeat. Finds independent rules iteratively. |
| **Multi-Depth Cascading** | Extract rules from trees at different depths (3, 5, 7). Each depth captures patterns at different granularity. Combine all rules into one gate. |
| **Feature Interactions** | Auto-generated cross-feature products (age × education, hours × marital_status). Gives the tree oblique decision boundaries it cannot find from raw features alone. |
| **Weighted Formula** | A logistic regression score (`w1*f1 + w2*f2 + ... > threshold`) used as a single gate feature. Captures linear combinations that threshold rules cannot express. |

## LLM Integration (optional)

| Term | Definition |
|---|---|
| **LLM Trace Synthesis** | Using an LLM during setup to generate candidate labeled traces from an English policy or behavior description. The traces should be reviewed, audited, and treated as synthetic evidence, not as automatic truth. |
| **LLM Rule Critique** | After discovery, an LLM reviews rules against the original policy and generates counterexample traces for overgeneralized rules. |
| **LLM Observer Synthesis** | Using an LLM to generate a deterministic observer or adapter spec that maps raw domain artifacts into the normalized feature contract consumed by Gate IR. |
| **LLM Runtime Extraction** | Using an LLM inside an observer at runtime to extract candidate assertions from freeform domain artifacts. This is acceptable when the extracted assertions remain provenance-carrying and advisory until reviewed. |
| **Model As Observer** | Using a model directly as the observer layer for messy language, documents, images, or other ambiguous inputs. The model's job is to normalize or extract, not to silently own the final consequential logic. |
| **Pearl-Guarded AI** | An AI system that calls pearls for deterministic policy checks, exact decision logic, or bounded knowledge instead of relying on freeform model reasoning alone. This lets AI stay flexible at the edge while pearls keep the core exact. |

## Production Features

| Term | Definition |
|---|---|
| **Drift Detection** | Per-rule accuracy monitoring over a sliding window. When a rule's precision or recall drops below baseline, generates an alert identifying which rule, which metric, and how much it degraded. |
| **Semantic Obfuscation** | A compiled artifact may omit human-readable labels and retain only numeric indices and thresholds. The logic is preserved but the surface intent is stripped. |
| **Route Status** | The workflow routing decision emitted around the pearl result, such as `ready_for_clinical_review`, `missing_required_documentation`, or `needs_human_review`. This is not the same thing as approve/deny. |
| **Review Packet** | The organized output package for a human reviewer: case summary, guided-question outcomes, matched evidence, missing documentation, and audit notes. |

## OPA/Rego Integration

| Term | Definition |
|---|---|
| **Rego Transpiler** | Static code generator that reads a `.rego` file via `opa parse`, walks the AST, and emits observer + LogicPearl gate code. |
| **Rego Interpreter** | Dynamic AST walker that evaluates Rego policies directly at runtime. Slower than transpiled code but handles new patterns automatically. |
| **OPA Parser Dependency** | LogicPearl uses `opa parse --format json` to convert `.rego` files to AST. OPA handles syntax; LogicPearl handles evaluation. |

## Architecture Separation

| Layer | What it does | Can be complex? | Changes when? |
|---|---|---|---|
| **Observer / Adapter Layer** | Convert raw input into normalized, typed features or candidate assertions. May include deterministic transforms and AI-assisted extraction over freeform evidence. | Yes | When input formats or domain semantics change |
| **Assertion Review Layer** | Filter, validate, corroborate, or escalate candidate assertions before they are treated as trusted evidence. | Yes | When evidence-trust policy changes |
| **Feature Contract** | The typed schema emitted by the observer layer and consumed by Gate IR. In freeform domains, this may be derived from reviewed assertions plus structured facts. | No | When the observer boundary changes |
| **Gate** | Check normalized features against deterministic rules and produce a bitmask. | No | When rules change (re-discovery) |
| **Escalation Path** | Handle ambiguous or escalated verdicts. | Yes | When escalation policy changes |

The key separation is simple:
- complexity can live in observers, assertion review, and adapters
- the pearl or gate should stay compact, deterministic, and explainable
