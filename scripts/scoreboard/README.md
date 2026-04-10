# Scoreboard Scripts

These scripts keep a small public score ledger for LogicPearl.

Fast path:
- `cargo xtask refresh-benchmarks`

Additional `xtask` commands:
- `cargo xtask scoreboard-update`
- `cargo xtask contributor-points`
- `cargo xtask contributor-summary`

The Python files in this folder remain as supplementary reference tooling.

## Files

- `update_scores.py`
  - measures checked-in examples and the fast guardrail regression sample
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

Run the full public refresh flow in one command:

```bash
cargo xtask refresh-benchmarks
```

or from the project root:

```bash
scripts/refresh_all_benchmarks.sh
```

That wrapper runs workspace validation, guardrail rebuild/eval, WAF rebuild/eval, and the scoreboard refresh.

Refresh the root score ledger with:

```bash
cargo xtask scoreboard-update
```

Rebuild contributor points from git history with:

```bash
cargo xtask contributor-points
cargo xtask contributor-summary
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
  - to the project `gh-pages` branch, with prior history retained

## Contributor Attribution

For fair contributor tracking, prefer merge strategies that preserve author identity on `main`.

Important caveat:
- if a squash merge rewrites the author identity, the score history will attribute that improvement to the squash commit author
- if authors use GitHub no-reply emails, the history script will infer the GitHub login when possible

The current model is best suited to:
- merge commits
- rebase-and-merge
- squash merges that preserve the contributor as author
