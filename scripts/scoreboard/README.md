# Scoreboard Scripts

These scripts keep a small public score ledger for LogicPearl.

## Files

- `update_scores.py`
  - measures the current public repo against checked-in examples and the fast guardrail regression sample
  - records guardrail scores under the active `target_goal` lane from the frozen bundle manifest
  - writes the root [`SCORES.json`](../../SCORES.json)

- `compute_contributor_points.py`
  - walks git history for `SCORES.json`
  - computes per-commit suite deltas
  - gives every scored `main` commit a base participation point
  - aggregates weighted improvement points per contributor using `score_model.json`
  - publishes contributor-friendly scoring terms:
    - `shells` = participation points
    - `pearls` = improvement points
    - `treasure` = total points

- `build_contributor_summary.py`
  - derives a small leaderboard-friendly summary from `contributor_points.json`
  - intended as the default frontend endpoint for contributor ranking pages

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
- Guardrail sampled baselines are lane-aware:
  - the runner prefers `open_guardrail_regression_baseline.sample200.<target-goal>.json`
  - `SCORES.json` keeps the active lane under `guardrails_open_sample200.by_target_goal`
- If that bundle is unavailable, the score ledger records the guardrail suite as unavailable instead of failing.
- Raw metrics live in `SCORES.json`.
- Contributor points are intentionally computed from curated suite-level scores instead of summing every numeric metric.
- Contributor totals are split into:
  - `participation_points`
  - `improvement_points`
  - `total_points`
- The published JSON also includes friendly labels:
  - `shells`
  - `pearls`
  - `treasure`
- That keeps correlated metrics from being double-counted and makes it easier to add new benchmarks without silently changing the total point budget.
- `.github/workflows/scores.yml` publishes:
  - `latest/SCORES.json`
  - `latest/contributor_points.json`
  - `latest/contributor_summary.json`
  - `latest/score_model.json`
  - plus per-commit snapshots under `history/<commit>/`
  - to the repo's `gh-pages` branch, with prior history retained

## Contributor Attribution

For fair contributor tracking, prefer merge strategies that preserve author identity on `main`.

Important caveat:
- if a maintainer squash-merges a PR and rewrites the author identity, the score history will attribute that improvement to the squash commit author
- if authors use GitHub no-reply emails, the history script will infer the GitHub login when possible

The current model is best suited to:
- merge commits
- rebase-and-merge
- squash merges that preserve the contributor as author
