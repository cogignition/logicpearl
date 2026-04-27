# Discovery Engine

LogicPearl discovery turns reviewed traces into a deterministic policy
artifact. The engine is intentionally layered so rule-learning changes have a
clear home and `engine.rs` can stay mostly orchestration.

The gate discovery path is:

```text
trace loading
  -> atomic candidates
  -> bottom-up conjunctions
  -> greedy lookahead
  -> exact selection
  -> rare recovery
  -> generalization
  -> tightening
  -> rule text
```

## Trace Loading

Trace loading happens before the engine sees rows. It normalizes CSV, JSON, or
JSONL inputs into `DecisionTraceRow` values with raw feature values and a
reviewed target.

Relevant code:

- `crates/logicpearl-discovery/src/trace_loading.rs`
- `crates/logicpearl-discovery/src/lib.rs`

Keep this layer about input shape and target inference. Do not add rule
learning, feature semantics, or domain-specific feature ID parsing here.
Reviewer-facing feature meaning should come from a feature dictionary.

## Atomic Candidates

Atomic candidate generation enumerates single-predicate rules from reviewed
rows. It is responsible for:

- numeric thresholds and exact numeric guards
- boolean predicates
- string equality predicates
- feature-reference numeric comparisons
- candidate coverage and false-positive counts
- candidate priority scoring helpers

Relevant code:

- `crates/logicpearl-discovery/src/engine/candidates.rs`
- `crates/logicpearl-discovery/src/engine/scoring.rs`

This layer should produce simple `CandidateRule` values. It should not decide
the final policy plan.

## Bottom-Up Conjunctions

Bottom-up conjunction search expands strong atomic predicates into compound
rules. It ranks atoms by signal, grows conjunctions level by level, and keeps a
bounded frontier at each level.

Relevant code:

- `crates/logicpearl-discovery/src/engine/bottom_up.rs`

This layer exists to keep compound rules understandable. Larger conjunctions
should be explored as refinements of useful smaller predicates, not as opaque
solver fragments. It should emit candidate rules, not final rules.

## Greedy Lookahead

Greedy selection builds a candidate plan one rule at a time. For each pass it
evaluates a bounded candidate frontier with lookahead, simulates the resulting
plan, and chooses the next candidate according to the active selection policy.

Relevant code:

- `crates/logicpearl-discovery/src/engine.rs`
- `crates/logicpearl-discovery/src/engine/scoring.rs`

This layer is policy-aware:

- balanced selection prioritizes total training and validation error, then
  false positives and simpler plans
- recall-biased selection prioritizes recall targets while respecting the
  configured false-positive cap

Greedy lookahead should stay focused on plan construction. Candidate
enumeration belongs in `candidates.rs` or `bottom_up.rs`; selected-plan cleanup
belongs in generalization, tightening, and rule hygiene.

## Exact Selection

Exact selection receives a shortlist from greedy discovery and candidate
priority frontiers. It searches for a smaller or better-scoring selected set
under the same policy.

Relevant code:

- `crates/logicpearl-discovery/src/engine/selection.rs`
- `crates/logicpearl-discovery/src/engine/scoring.rs`

The shortlist is deliberately mixed: high-priority candidates, balanced
compound candidates, and the greedy plan. This keeps exact selection from
missing low-error compound plans when broad signal-first ranking produces many
nearby candidates.

## Rare Recovery

Rare recovery checks whether selected rules missed denied slices that the main
plan could still cover without making the score worse. It regenerates
candidates against uncovered denied rows and adopts rescue rules only when the
combined plan improves.

Relevant code:

- `crates/logicpearl-discovery/src/engine.rs`
- `crates/logicpearl-discovery/src/engine/residual_recovery.rs`

This stage is for missed slices after plan selection. It should not become the
primary conjunction learner.

## Generalization

Generalization loosens over-specific selected candidate rules after greedy and
exact selection are done. It is score-aware and uses the active selection
policy.

Relevant code:

- `crates/logicpearl-discovery/src/engine/generalization.rs`

Current responsibilities:

- drop individual conjuncts from selected compound rules when the whole-plan
  score is no worse
- remove selected rules that are strictly subsumed by broader selected rules
  on training rows when removal does not worsen the whole-plan score

This layer is the right place for Occam-style loosening over selected rules. It
should operate on candidate match sets and policy scores, not on domain meaning
or display labels.

## Tightening

Tightening narrows over-broad artifact rules by adding conditions. This is the
internal name for the behavior exposed by the stable CLI flag `--refine`.

Relevant code:

- `crates/logicpearl-discovery/src/engine/residual_recovery.rs`

Tightening is intentionally separate from generalization:

- generalization removes unnecessary conditions or redundant selected rules
- tightening adds conditions to reduce unique false positives

Keep CLI wording compatible, but use `tightening` in engine code and docs when
describing this narrowing pass.

## Rule Text

Rule text renders selected candidates into artifact rules with labels,
messages, counterfactual hints, evidence, and feature-dictionary semantics.
Runtime behavior still comes from raw expressions.

Relevant code:

- `crates/logicpearl-discovery/src/rule_text.rs`
- `crates/logicpearl-discovery/src/engine.rs`

Do not repair unreadable output by editing labels after discovery. Generate a
feature dictionary from the same source that generated the traces, pass it to
build or discover, and let rule text generation embed the reviewer-facing
metadata into the artifact.

## Where New Work Belongs

Use these boundaries when adding discovery behavior:

- new predicate families: `candidates.rs`
- new compound-rule search strategy: `bottom_up.rs` or a sibling module
- candidate-set scoring changes: `scoring.rs`
- shortlist or exact-search behavior: `selection.rs`
- selected-plan generalization: `generalization.rs`
- over-broad rule tightening: `residual_recovery.rs`
- final rule dedupe, merge, or canonical cleanup: `rule_hygiene.rs`
- output labels, messages, and hints: `rule_text.rs`
- orchestration only: `engine.rs`

If a change needs many edits in `engine.rs`, first check whether a stage module
is missing.

## Invariants

Discovery changes should preserve these invariants:

- core crates treat feature IDs as opaque strings
- feature dictionaries affect explanations, not runtime bitmasks
- candidate generation does not choose final policy plans
- selection policies are applied consistently in greedy, exact, recovery,
  generalization, and tightening steps
- generalization may only remove or loosen selected rules when whole-plan
  score is no worse
- rule text is generated from selected raw expressions and optional feature
  semantics, not from downstream UI rewrites

## Tests

For engine changes, add tests that name the behavior being protected. Useful
fixture shapes include:

- broad signal beats narrow fragments
- imbalanced prior rejects baseline-only rules
- bottom-up conjunctions retain useful broad compound rules
- balanced selection preserves zero-false-positive exact policies
- recall-biased selection meets recall under a false-positive cap
- generalization drops redundant conjuncts
- generalization drops selected rules subsumed by broader selected rules
- generalization replaces shard groups with a shared prefix rule when the
  whole-plan score is no worse
- tightening narrows over-broad rules only when unique false positives improve

Run at least:

```bash
cargo test -p logicpearl-discovery
```

For CLI-visible changes, also run the relevant `logicpearl` e2e test.
