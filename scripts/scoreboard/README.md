# Scoreboard Scripts

These scripts keep a small public score ledger for LogicPearl.

## Files

- `update_scores.py`
  - measures the current public repo against checked-in examples and the fast guardrail regression sample
  - writes the root [`SCORES.json`](/Users/missingno/Documents/LogicPearl/logicpearl/SCORES.json)

- `compute_contributor_points.py`
  - walks git history for `SCORES.json`
  - computes per-commit suite deltas
  - aggregates a weighted improvement score per contributor using `score_model.json`

- `score_model.json`
  - defines the curated scoring model for contributor points
  - keeps total suite budgets fixed so adding more raw metrics later does not automatically distort the points system

## Current Measured Suites

- getting started artifact build + run
- demo datasets:
  - `access_control`
  - `content_moderation`
  - `loan_approval`
- fast guardrail regression sample:
  - `JailbreakBench`
  - `PromptShield`
  - `rogue-security/prompt-injections-benchmark`

## Usage

Refresh the root score ledger:

```bash
python3 scripts/scoreboard/update_scores.py
```

Rebuild contributor points from git history:

```bash
python3 scripts/scoreboard/compute_contributor_points.py
```

## Notes

- The guardrail sample uses the frozen bundle pointed to by `LOGICPEARL_GUARDRAIL_BUNDLE_DIR`.
- If that bundle is unavailable, the score ledger records the guardrail suite as unavailable instead of failing.
- Raw metrics live in `SCORES.json`.
- Contributor points are intentionally computed from curated suite-level scores instead of summing every numeric metric.
- That keeps correlated metrics from being double-counted and makes it easier to add new benchmarks without silently changing the total point budget.
- `.github/workflows/scores.yml` publishes:
  - `latest/SCORES.json`
  - `latest/contributor_points.json`
  - `latest/score_model.json`
  - plus per-commit snapshots under `history/<commit>/`

## Contributor Attribution

For fair contributor tracking, prefer merge strategies that preserve author identity on `main`.

Important caveat:
- if a maintainer squash-merges a PR and rewrites the author identity, the score history will attribute that improvement to the squash commit author
- if authors use GitHub no-reply emails, the history script will infer the GitHub login when possible

The current model is best suited to:
- merge commits
- rebase-and-merge
- squash merges that preserve the contributor as author
