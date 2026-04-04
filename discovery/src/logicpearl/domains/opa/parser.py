from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RegoPolicyMetadata:
    package: str
    rule_names: list[str]
    default_rules: list[str]
    source_path: Path


def parse_rego_ast(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path)
    result = subprocess.run(
        ["opa", "parse", "--format", "json", str(policy_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"opa parse failed for {policy_path}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def infer_rego_policy_metadata(path: str | Path) -> RegoPolicyMetadata:
    policy_path = Path(path)
    ast = parse_rego_ast(policy_path)
    package = _extract_package(ast)
    rule_names, default_rules = _extract_rule_names(ast)
    return RegoPolicyMetadata(
        package=package,
        rule_names=rule_names,
        default_rules=default_rules,
        source_path=policy_path,
    )


def evaluate_rego_query(
    policy_path: str | Path,
    *,
    query: str,
    input_data: dict[str, Any],
    timeout_seconds: float = 5.0,
) -> Any:
    result = subprocess.run(
        ["opa", "eval", "-d", str(policy_path), "--stdin-input", query],
        input=json.dumps(input_data),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    if result.returncode != 0:
        raise RuntimeError(f"opa eval failed for {policy_path}: {result.stderr.strip()}")
    payload = json.loads(result.stdout)
    return payload["result"][0]["expressions"][0]["value"]


def _extract_package(ast: dict[str, Any]) -> str:
    package = ast.get("package")
    if not isinstance(package, dict):
        raise ValueError("OPA AST did not contain a package section")
    parts = []
    for item in package.get("path", []):
        value = item.get("value")
        if isinstance(value, str):
            parts.append(value)
    if parts and parts[0] == "data":
        parts = parts[1:]
    if not parts:
        raise ValueError("OPA AST package path was empty")
    return ".".join(parts)


def _extract_rule_names(ast: dict[str, Any]) -> tuple[list[str], list[str]]:
    rules: list[str] = []
    defaults: list[str] = []
    for item in ast.get("rules", []):
        head = item.get("head", {})
        name = head.get("name")
        if isinstance(name, str):
            rules.append(name)
            if item.get("default"):
                defaults.append(name)
    return sorted(set(rules)), sorted(set(defaults))
