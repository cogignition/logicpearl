#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "scoreboard" / "contributor_points.json"
SCORE_MODEL_PATH = REPO_ROOT / "scripts" / "scoreboard" / "score_model.json"
PARTICIPATION_POINTS_PER_COMMIT = 1.0
SCORING_TERMS = {
    "participation_points": {
        "display_name": "shells",
        "description": "Base credit for anything that lands on main.",
    },
    "improvement_points": {
        "display_name": "pearls",
        "description": "Extra credit earned by improving measured scores.",
    },
    "total_points": {
        "display_name": "treasure",
        "description": "Total score, combining shells and pearls.",
    },
}


def parse_args() -> Path:
    output = DEFAULT_OUTPUT
    args = sys.argv[1:]
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--output":
            index += 1
            output = Path(args[index]).resolve()
        else:
            raise SystemExit(f"unknown argument: {arg}")
        index += 1
    return output


def git_output(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def load_scores_for_commit(commit: str) -> dict[str, Any] | None:
    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"{commit}:SCORES.json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def load_score_model() -> dict[str, Any]:
    return json.loads(SCORE_MODEL_PATH.read_text(encoding="utf-8"))


def infer_github_login(email: str) -> str | None:
    lowered = email.strip().lower()
    if not lowered.endswith("@users.noreply.github.com"):
        return None
    local = lowered[: -len("@users.noreply.github.com")]
    if "+" in local:
        return local.split("+", 1)[1] or None
    return local or None


def suite_score(scores: dict[str, Any], suite_model: dict[str, Any]) -> float:
    metrics = scores.get("metrics", {})
    total = 0.0
    for metric_spec in suite_model["metrics"]:
        metric = metrics.get(metric_spec["id"])
        if metric is None:
            continue
        total += float(metric["value"]) * float(metric_spec["weight"])
    return total


def main() -> int:
    output_path = parse_args()
    score_model = load_score_model()
    score_commits = (
        git_output(
            "log",
            "--reverse",
            "--format=%H",
            "--",
            "SCORES.json",
        )
        .splitlines()
    )
    if not score_commits:
        raise SystemExit("no SCORES.json history found")
    first_score_commit = score_commits[0]
    log_lines = git_output(
        "log",
        "--reverse",
        "--format=%H\t%an\t%ae\t%aI",
        f"{first_score_commit}^..HEAD",
    ).splitlines()

    commits: list[dict[str, Any]] = []
    contributor_points: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "author_name": "",
            "author_email": "",
            "github_login": None,
            "participation_points": 0.0,
            "improvement_points": 0.0,
            "total_points": 0.0,
            "commits": [],
        }
    )

    previous_scores: dict[str, Any] | None = None
    for line in log_lines:
        commit, author_name, author_email, authored_at = line.split("\t", 3)
        github_login = infer_github_login(author_email)
        contributor_key = github_login or author_email
        current_scores = load_scores_for_commit(commit)
        if current_scores is None:
            current_scores = previous_scores

        suite_changes: dict[str, Any] = {}
        improvement_points = 0.0
        if previous_scores is not None and current_scores is not None:
            for suite_model in score_model["suites"]:
                suite_id = suite_model["id"]
                previous_suite_score = suite_score(previous_scores, suite_model)
                current_suite_score = suite_score(current_scores, suite_model)
                delta = current_suite_score - previous_suite_score
                if abs(delta) < 1e-12:
                    continue
                weighted_points = max(delta, 0.0) * float(suite_model["points_budget"])
                suite_changes[suite_id] = {
                    "previous_score": previous_suite_score,
                    "current_score": current_suite_score,
                    "delta": delta,
                    "points_budget": suite_model["points_budget"],
                    "weighted_points": weighted_points,
                    "metrics": suite_model["metrics"],
                }
                improvement_points += weighted_points

        participation_points = PARTICIPATION_POINTS_PER_COMMIT
        total_points = participation_points + improvement_points
        commit_entry = {
            "commit": commit,
            "author_name": author_name,
            "author_email": author_email,
            "github_login": github_login,
            "authored_at": authored_at,
            "participation_points": participation_points,
            "improvement_points": improvement_points,
            "total_points": total_points,
            "shells": participation_points,
            "pearls": improvement_points,
            "treasure": total_points,
            "suite_changes": suite_changes,
        }
        commits.append(commit_entry)
        contributor = contributor_points[contributor_key]
        contributor["author_name"] = author_name
        contributor["author_email"] = author_email
        contributor["github_login"] = github_login
        contributor["participation_points"] += participation_points
        contributor["improvement_points"] += improvement_points
        contributor["total_points"] += total_points
        contributor["shells"] = contributor["participation_points"]
        contributor["pearls"] = contributor["improvement_points"]
        contributor["treasure"] = contributor["total_points"]
        contributor["points"] = contributor["total_points"]
        contributor["commits"].append(
            {
                "commit": commit,
                "authored_at": authored_at,
                "participation_points": participation_points,
                "improvement_points": improvement_points,
                "total_points": total_points,
                "shells": participation_points,
                "pearls": improvement_points,
                "treasure": total_points,
            }
        )
        if current_scores is not None:
            previous_scores = current_scores

    payload = {
        "schema_version": "1.0",
        "generated_by": "scripts/scoreboard/compute_contributor_points.py",
        "participation_points_per_commit": PARTICIPATION_POINTS_PER_COMMIT,
        "scoring_terms": SCORING_TERMS,
        "score_model": score_model,
        "commits": commits,
        "contributors": sorted(
            contributor_points.values(),
            key=lambda item: (-item["total_points"], item["github_login"] or item["author_email"]),
        ),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
