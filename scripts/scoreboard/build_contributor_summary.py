#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_INPUT = REPO_ROOT / "scripts" / "scoreboard" / "contributor_points.json"
DEFAULT_OUTPUT = REPO_ROOT / "scripts" / "scoreboard" / "contributor_summary.json"


def parse_args() -> tuple[Path, Path]:
    input_path = DEFAULT_INPUT
    output_path = DEFAULT_OUTPUT
    args = sys.argv[1:]
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--input":
            index += 1
            input_path = Path(args[index]).resolve()
        elif arg == "--output":
            index += 1
            output_path = Path(args[index]).resolve()
        else:
            raise SystemExit(f"unknown argument: {arg}")
        index += 1
    return input_path, output_path


def main() -> int:
    input_path, output_path = parse_args()
    contributor_points = json.loads(input_path.read_text(encoding="utf-8"))
    contributors: list[dict[str, Any]] = contributor_points.get("contributors", [])

    summary = {
        "schema_version": "1.0",
        "generated_by": "scripts/scoreboard/build_contributor_summary.py",
        "contributors": [],
    }
    for index, contributor in enumerate(contributors, start=1):
        commits = contributor.get("commits", [])
        latest_commit = commits[-1] if commits else None
        summary["contributors"].append(
            {
                "rank": index,
                "author_name": contributor.get("author_name"),
                "author_email": contributor.get("author_email"),
                "github_login": contributor.get("github_login"),
                "participation_points": contributor.get("participation_points", 0.0),
                "improvement_points": contributor.get("improvement_points", 0.0),
                "total_points": contributor.get("total_points", contributor.get("points", 0.0)),
                "points": contributor.get("total_points", contributor.get("points", 0.0)),
                "commit_count": len(commits),
                "latest_commit": latest_commit,
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
