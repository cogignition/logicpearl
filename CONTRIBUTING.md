# Contributing

LogicPearl is a small public product repo with a visible scoreboard.

The goal is not just to land code. The goal is to make the public engine better:
- easier to run
- easier to inspect
- more honest on parity and benchmarks
- more generic, not more benchmark-shaped

## The Scoreboard

Every commit that lands on `main` earns at least **1 shell**.

If that commit improves the measured public score suites, it also earns **pearls**.

- `shells`
  - base participation credit
  - you get these for shipping real work to `main`
- `pearls`
  - improvement credit
  - you get these when the measured repo scores improve
- `treasure`
  - total score
  - `shells + pearls`

The scoreboard is generated from:
- checked-in examples
- demo datasets
- the fast open guardrail regression sample

Files:
- [SCORES.json](./SCORES.json)
- [scripts/scoreboard/README.md](./scripts/scoreboard/README.md)
- [scripts/scoreboard/score_model.json](./scripts/scoreboard/score_model.json)

## How To Earn More Pearls

High-value contribution patterns:
- improve the generic engine so more datasets build cleanly without special handling
- improve runtime, IR, validation, or inspection tooling
- improve observer synthesis or benchmark infrastructure in ways that stay generic
- add honest examples, tests, and docs that strengthen the public first-run path
- reduce regressions and keep benchmarks reproducible

Low-value or rejected patterns:
- benchmark-specific hacks disguised as generic features
- demo-only shortcuts in shared engine code
- claims in docs that overstate what a benchmark proves
- changes that make the public repo feel magical only because hidden assumptions were baked in

The fastest way to lose the plot here is optimizing for score movement while making the engine less honest.

## Design Rules

Keep the engine generic.

Good:
- feature support that works across multiple datasets
- discovery improvements that do not mention one benchmark by name
- better simplification, validation, or runtime behavior

Bad:
- hardcoded benchmark heuristics in shared discovery/runtime code
- public UX shaped around one private workflow
- synthetic demos that only work because the engine secretly special-cases them

## Before You Open A PR

Please make sure:
- tests pass
- new public docs are accurate and conservative
- benchmark framing matches what the code actually proves
- score movement, if any, comes from a generic improvement

If your change is score-neutral but makes the repo cleaner, easier to use, or more honest, it is still a good contribution. You still earn shells for landing it.

## Local Development

Run the full public test suite:

```bash
cargo test --workspace
```

Refresh the public score ledger:

```bash
python3 scripts/scoreboard/update_scores.py
```

Rebuild contributor totals:

```bash
python3 scripts/scoreboard/compute_contributor_points.py
python3 scripts/scoreboard/build_contributor_summary.py
```

## Attribution

Contributor tracking is based on git history.

For the cleanest attribution on `main`:
- preserve the original author when merging
- prefer merge strategies that keep contributor identity intact
- if you use GitHub no-reply emails, the scoreboard will infer the GitHub login when possible

If a maintainer rewrites authorship during squash merge, the scoreboard will attribute the shells and pearls to the squash author.
