# Quality Report Scripts

These scripts generate local quality reports for LogicPearl examples and benchmark smoke suites. The report is not checked into the repository.

Fast path:

```bash
cargo xtask refresh-benchmarks
```

Refresh only the quality report:

```bash
cargo xtask quality-report
```

The Python generator is supplementary reference tooling:

```bash
scripts/quality/update_quality.py
```

## Files

- `update_quality.py`
  - measures checked-in examples and the fast guardrail regression sample
  - records guardrail metrics under the active `target_goal` lane from the frozen bundle manifest
  - writes `target/logicpearl/quality/QUALITY.json` by default

## Current Measured Suites

- getting started artifact build and run
- demo datasets:
  - `access_control`
  - `content_moderation`
  - `loan_approval`
- fast guardrail regression sample:
  - `JailbreakBench`
  - `PromptShield`
  - `rogue-security/prompt-injections-benchmark`

## Notes

- The guardrail sample uses the frozen bundle pointed to by `LOGICPEARL_GUARDRAIL_BUNDLE_DIR`.
- Guardrail sampled baselines are lane-aware:
  - the runner prefers `open_guardrail_regression_baseline.sample200.<target-goal>.json`
  - the generated report keeps the active lane under `guardrails_open_sample200.by_target_goal`
- If that bundle is unavailable, the quality report records the guardrail suite as unavailable instead of failing.
- Raw metrics live in the generated local report.
- Contributor points and public leaderboards are intentionally not part of the public OSS quality report.
- GitHub Pages publication for quality data is intentionally disabled; consumers should use explicit CI or release artifacts when a public quality snapshot is needed.
