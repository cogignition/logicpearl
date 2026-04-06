#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_cases(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def first_match(rows: list[dict], predicate, label: str) -> dict:
    for row in rows:
        if predicate(row):
            return row
    raise SystemExit(f"could not find demo case for {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the checked-in WAF demo slice from adapted real benchmark cases.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "examples" / "waf_edge")
    args = parser.parse_args()

    rows = load_cases(args.input)
    output_dir = args.output_dir.resolve()

    allow = first_match(
        rows,
        lambda row: row["expected_route"] == "allow"
        and any(
            marker in row["input"].get("path", "")
            for marker in ("index.jsp", "/publico/caracteristicas.jsp", "/publico/entrar.jsp")
        ),
        "allow",
    )
    sqli = first_match(
        rows,
        lambda row: row["expected_route"] == "deny_injection_payload"
        and row["input"].get("waf_dataset") == "csic-http-2010"
        and "sqli" in (row.get("category") or ""),
        "sqli",
    )
    restricted = first_match(
        rows,
        lambda row: row["expected_route"] == "deny_sensitive_surface"
        and any(
            marker in row["input"].get("path", "")
            for marker in (".ini", "/.git", "/.env")
        ),
        "restricted",
    )
    review = first_match(
        rows,
        lambda row: row["expected_route"] == "review_suspicious_request",
        "review",
    )

    demo_rows = [
        allow,
        sqli,
        restricted,
        review,
    ]

    write_jsonl(output_dir / "dev_cases.jsonl", demo_rows)
    (output_dir / "input_allow.json").write_text(json.dumps(allow["input"], indent=2) + "\n")
    (output_dir / "input_block_sqli.json").write_text(json.dumps(sqli["input"], indent=2) + "\n")
    (output_dir / "input_block_sensitive.json").write_text(json.dumps(restricted["input"], indent=2) + "\n")
    (output_dir / "input_review_probe.json").write_text(json.dumps(review["input"], indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
