#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

guardrail_bundle_dir="${LOGICPEARL_GUARDRAIL_BUNDLE_DIR:-/private/tmp/guardrails_bundle}"
waf_benchmark_dir="${LOGICPEARL_WAF_BENCHMARK_DIR:-/private/tmp/waf_benchmark}"
waf_learned_bundle_dir="${LOGICPEARL_WAF_LEARNED_BUNDLE_DIR:-/private/tmp/waf_learned_bundle}"
target_goal="${LOGICPEARL_TARGET_GOAL:-protective-gate}"
guardrail_sample_size=""
resume=false
skip_validate=false
use_installed_cli=false

usage() {
  cat <<EOF
Usage: scripts/refresh_all_benchmarks.sh [options]

Run the full public LogicPearl validation + benchmark refresh flow:
  1. cargo clippy / cargo test
  2. full guardrail bundle rebuild and external benchmark eval
  3. WAF benchmark corpus rebuild and learned WAF bundle rebuild
  4. scoreboard refresh

Options:
  --resume                   Resume long-running bundle rebuilds where supported
  --skip-validate            Skip cargo clippy / cargo test
  --use-installed-cli        Pass --use-installed-cli through to Python bundle builders
  --target-goal GOAL         Guardrail target goal (default: ${target_goal})
  --guardrail-bundle-dir DIR Guardrail bundle output dir
  --waf-benchmark-dir DIR    WAF benchmark corpus output dir
  --waf-bundle-dir DIR       Learned WAF bundle output dir
  --guardrail-sample-size N  Run sampled guardrail eval instead of full final_holdout eval
  -h, --help                 Show this help

Environment overrides:
  LOGICPEARL_GUARDRAIL_BUNDLE_DIR
  LOGICPEARL_WAF_BENCHMARK_DIR
  LOGICPEARL_WAF_LEARNED_BUNDLE_DIR
  LOGICPEARL_TARGET_GOAL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resume)
      resume=true
      shift
      ;;
    --skip-validate)
      skip_validate=true
      shift
      ;;
    --use-installed-cli)
      use_installed_cli=true
      shift
      ;;
    --target-goal)
      target_goal="$2"
      shift 2
      ;;
    --guardrail-bundle-dir)
      guardrail_bundle_dir="$2"
      shift 2
      ;;
    --waf-benchmark-dir)
      waf_benchmark_dir="$2"
      shift 2
      ;;
    --waf-bundle-dir)
      waf_learned_bundle_dir="$2"
      shift 2
      ;;
    --guardrail-sample-size)
      guardrail_sample_size="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

run() {
  echo "+ $*"
  "$@"
}

guardrail_build_args=(
  python3
  scripts/guardrails/build_guardrail_bundle.py
  --output-dir
  "$guardrail_bundle_dir"
  --target-goal
  "$target_goal"
)
if [[ "$resume" == true ]]; then
  guardrail_build_args+=(--resume)
fi
if [[ "$use_installed_cli" == true ]]; then
  guardrail_build_args+=(--use-installed-cli)
fi

waf_build_args=(
  python3
  scripts/waf/build_waf_learned_bundle.py
  --output-dir
  "$waf_learned_bundle_dir"
  --benchmark-dir
  "$waf_benchmark_dir"
  --residual-pass
  --refine
)
if [[ "$resume" == true ]]; then
  waf_build_args+=(--resume)
fi
if [[ "$use_installed_cli" == true ]]; then
  waf_build_args+=(--use-installed-cli)
fi

guardrail_eval_args=(
  python3
  scripts/guardrails/run_open_guardrail_benchmarks.py
  --bundle-dir
  "$guardrail_bundle_dir"
  --input-split
  final_holdout
  --output-dir
  "$guardrail_bundle_dir/open_benchmarks_final_holdout"
)
if [[ -n "$guardrail_sample_size" ]]; then
  guardrail_eval_args+=(--sample-size "$guardrail_sample_size")
fi

cd "$repo_root"
export LOGICPEARL_GUARDRAIL_BUNDLE_DIR="$guardrail_bundle_dir"

if [[ "$skip_validate" != true ]]; then
  run cargo clippy --workspace --all-targets -- -D warnings
  run cargo test --workspace
fi

run python3 scripts/guardrails/freeze_guardrail_holdouts.py
run "${guardrail_build_args[@]}"
run "${guardrail_eval_args[@]}"

run python3 scripts/waf/build_waf_benchmark_cases.py --output-dir "$waf_benchmark_dir"
run "${waf_build_args[@]}"

run python3 scripts/scoreboard/update_scores.py
run python3 scripts/scoreboard/compute_contributor_points.py
run python3 scripts/scoreboard/build_contributor_summary.py

echo
echo "Refresh complete."
echo "Guardrails summary: $guardrail_bundle_dir/open_benchmarks_final_holdout/summary.json"
echo "Learned WAF summary: $waf_learned_bundle_dir/summary.json"
echo "Score ledger: $repo_root/SCORES.json"
