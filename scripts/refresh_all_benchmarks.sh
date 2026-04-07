#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

guardrail_bundle_dir="${LOGICPEARL_GUARDRAIL_BUNDLE_DIR:-/private/tmp/guardrails_bundle}"
waf_benchmark_dir="${LOGICPEARL_WAF_BENCHMARK_DIR:-/private/tmp/waf_benchmark}"
waf_learned_bundle_dir="${LOGICPEARL_WAF_LEARNED_BUNDLE_DIR:-/private/tmp/waf_learned_bundle}"
target_goal="${LOGICPEARL_TARGET_GOAL:-protective-gate}"
logs_dir_default="/private/tmp/logicpearl_refresh_logs/$(date +%Y%m%d_%H%M%S)"
logs_dir="$logs_dir_default"
guardrail_sample_size=""
resume=false
skip_validate=false
use_installed_cli=false
verbose=false
heartbeat_interval=30

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
  --logs-dir DIR             Directory to write step logs into
  --verbose                  Stream full command output instead of concise status + logs
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
    --logs-dir)
      logs_dir="$2"
      shift 2
      ;;
    --verbose)
      verbose=true
      shift
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

timestamp() {
  date +"%H:%M:%S"
}

section() {
  echo
  echo "[$(timestamp)] $1"
}

run_step() {
  local step_id="$1"
  local title="$2"
  shift 2

  local log_file="$logs_dir/${step_id}.log"
  local started_at
  started_at="$(date +%s)"

  section "$title"
  echo "log: $log_file"

  if [[ "$verbose" == true ]]; then
    echo "+ $*"
    "$@" 2>&1 | tee "$log_file"
    return "${PIPESTATUS[0]}"
  fi

  "$@" >"$log_file" 2>&1 &
  local command_pid=$!

  while kill -0 "$command_pid" 2>/dev/null; do
    sleep "$heartbeat_interval"
    if kill -0 "$command_pid" 2>/dev/null; then
      local now
      now="$(date +%s)"
      echo "[$(timestamp)] still running (${title}) after $((now - started_at))s"
    fi
  done

  wait "$command_pid"
  local status=$?
  local finished_at
  finished_at="$(date +%s)"

  if [[ $status -ne 0 ]]; then
    echo "[$(timestamp)] failed: ${title}"
    echo "last log lines:"
    tail -n 40 "$log_file" || true
    return $status
  fi

  echo "[$(timestamp)] completed in $((finished_at - started_at))s"
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
mkdir -p "$logs_dir"

section "LogicPearl Refresh"
echo "repo: $repo_root"
echo "logs: $logs_dir"
echo "guardrails bundle: $guardrail_bundle_dir"
echo "waf benchmark dir: $waf_benchmark_dir"
echo "waf learned bundle: $waf_learned_bundle_dir"
echo "target goal: $target_goal"

if [[ "$skip_validate" != true ]]; then
  run_step 01_clippy "Workspace clippy" \
    cargo clippy --workspace --all-targets -- -D warnings
  run_step 02_tests "Workspace tests" \
    cargo test --workspace
fi

run_step 03_guardrails_freeze "Freeze guardrail holdouts" \
  python3 scripts/guardrails/freeze_guardrail_holdouts.py
run_step 04_guardrails_build "Build guardrail bundle" \
  "${guardrail_build_args[@]}"
run_step 05_guardrails_eval "Evaluate open guardrail benchmarks" \
  "${guardrail_eval_args[@]}"

run_step 06_waf_cases "Build WAF benchmark cases" \
  python3 scripts/waf/build_waf_benchmark_cases.py --output-dir "$waf_benchmark_dir"
run_step 07_waf_bundle "Build learned WAF bundle" \
  "${waf_build_args[@]}"

run_step 08_scores "Refresh score ledger" \
  python3 scripts/scoreboard/update_scores.py
run_step 09_contributor_points "Rebuild contributor points" \
  python3 scripts/scoreboard/compute_contributor_points.py
run_step 10_contributor_summary "Rebuild contributor summary" \
  python3 scripts/scoreboard/build_contributor_summary.py

echo
echo "Refresh complete."
echo "Logs: $logs_dir"
echo "Guardrails summary: $guardrail_bundle_dir/open_benchmarks_final_holdout/summary.json"
echo "Learned WAF summary: $waf_learned_bundle_dir/summary.json"
echo "Score ledger: $repo_root/SCORES.json"
