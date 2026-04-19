# Automatic Proposal Adoption

This example shows `logicpearl build` automatically running the proposal phase when deterministic recovery still has replay mismatches. The trace has two simple lending-style denial regions, but the command intentionally uses a one-rule budget so the proposal phase can find and safely adopt the missing relationship feature.

Run it from the repository root:

```sh
cargo build -p logicpearl
target/debug/logicpearl build examples/proposal_phase/traces.csv \
  --output-dir /tmp/logicpearl-proposal-phase \
  --max-rules 1 \
  --json
```

The generated pearl remains deterministic. By default, `auto_adopt_safe` only applies validated derived-feature proposals that fix mismatches, introduce no new training mismatches, and replay deterministically. `proposal_report.json` records:

- mismatch mining
- subgroup discovery
- derived feature search, including relationships such as `debt / income`
- small interpretable model search
- deterministic replay validation for each candidate
- accepted proposal IDs and the pre/post adoption parity

Inspect the proposal report:

```sh
cat /tmp/logicpearl-proposal-phase/proposal_report.json
```

Useful fields:

- `status`: whether the automatic phase ran
- `trigger`: why it ran
- `diagnosis`: the router's explanation of the failure mode
- `recommended_next_phase`: the next conservative action
- `acceptance_policy`: `auto_adopt_safe` by default
- `accepted_candidate_ids`: proposal IDs applied to the emitted pearl
- `pre_adoption_training_parity`: replay parity before proposal adoption
- `post_adoption_training_parity`: replay parity after proposal adoption
- `validated_candidates`: candidates that replay cleanly
- `stages`: structured phase summaries
- `candidates`: proposed regions/features/models with replay evidence and recommendation metadata

To inspect proposals without changing the emitted pearl, opt out explicitly:

```sh
target/debug/logicpearl build examples/proposal_phase/traces.csv \
  --output-dir /tmp/logicpearl-proposal-phase-report-only \
  --max-rules 1 \
  --proposal-policy report-only \
  --json
```
