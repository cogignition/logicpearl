from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

from pydantic import Field

from logicpearl.engine import compile_gate, compile_gate_to_wasm
from logicpearl.ir import LogicPearlGateIR
from logicpearl.ir.models import LogicPearlModel

from .evaluator import build_requirement_gate, requirement_feature_id
from .models import HealthcarePolicySlice
from .request_eval import HealthcarePolicyResponse, QuestionStatus


class RuntimeBitMapping(LogicPearlModel):
    bit: int
    rule_id: str
    requirement_id: str | None = None
    question_text: str | None = None
    cluster_id: str | None = None


class WasmArtifactInfo(LogicPearlModel):
    rust_source_path: str
    core_wasm_path: str | None = None
    core_wasm_size_bytes: int | None = None
    pearl_wasm_path: str | None = None
    pearl_wasm_size_bytes: int | None = None


class NativeRuntimeArtifactInfo(LogicPearlModel):
    binary_path: str | None = None
    binary_size_bytes: int | None = None
    build_succeeded: bool
    build_error: str | None = None
    invocation_template: str | None = None


class RuntimeArtifactBundle(LogicPearlModel):
    policy_id: str
    gate_path: str
    bit_manifest_path: str
    native_pearl_path: str | None = None
    wasm: WasmArtifactInfo
    native_runtime: NativeRuntimeArtifactInfo | None = None
    bit_mappings: list[RuntimeBitMapping] = Field(default_factory=list)


class NativeRuntimeCheck(LogicPearlModel):
    expected_bitmask: int
    native_bitmask: int | None = None
    parity_ok: bool
    command: str | None = None
    error: str | None = None


def run_native_pearl_check(
    *,
    native_pearl_path: str | Path,
    input_path: str | Path,
    expected_bitmask: int,
    timeout_seconds: float = 10.0,
) -> NativeRuntimeCheck:
    command = [str(native_pearl_path), "evaluate", "--input", str(input_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return NativeRuntimeCheck(
            expected_bitmask=expected_bitmask,
            parity_ok=False,
            command=" ".join(command),
            error=str(exc),
        )

    if result.returncode != 0:
        return NativeRuntimeCheck(
            expected_bitmask=expected_bitmask,
            parity_ok=False,
            command=" ".join(command),
            error=result.stderr.strip() or result.stdout.strip() or f"pearl exited {result.returncode}",
        )

    try:
        payload = json.loads(result.stdout)
        native_bitmask = int(payload["bitmask"])
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        return NativeRuntimeCheck(
            expected_bitmask=expected_bitmask,
            parity_ok=False,
            command=" ".join(command),
            error=f"unable to parse pearl output: {exc}",
        )

    return NativeRuntimeCheck(
        expected_bitmask=expected_bitmask,
        native_bitmask=native_bitmask,
        parity_ok=native_bitmask == expected_bitmask,
        command=" ".join(command),
    )


def export_runtime_artifacts(
    policy: HealthcarePolicySlice,
    gate: LogicPearlGateIR,
    *,
    output_dir: str | Path,
    runtime_root: str | Path | None = None,
    native_binary_path: str | Path | None = None,
    artifact_name: str = "pearl",
) -> RuntimeArtifactBundle:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    gate_path = output_path / f"{artifact_name}.ir.json"
    gate_path.write_text(gate.model_dump_json(indent=2), encoding="utf-8")

    compiled_gate = compile_gate(build_requirement_gate(policy))
    wasm_result = compile_gate_to_wasm(compiled_gate, output_dir=output_path, name=artifact_name)
    pearl_wasm_path = None
    pearl_wasm_size_bytes = None
    if wasm_result.wasm_path and wasm_result.wasm_path.exists():
        pearl_wasm = output_path / f"{artifact_name}.pearl.wasm"
        shutil.copy2(wasm_result.wasm_path, pearl_wasm)
        pearl_wasm_size_bytes = pearl_wasm.stat().st_size
        pearl_wasm_path = str(pearl_wasm)

    bit_mappings = build_runtime_bit_mappings(policy, gate)
    bit_manifest_path = output_path / f"{artifact_name}.bit_manifest.json"
    bit_manifest_path.write_text(
        json.dumps([mapping.model_dump(mode="json") for mapping in bit_mappings], indent=2),
        encoding="utf-8",
    )

    native_info: NativeRuntimeArtifactInfo | None = None
    if native_binary_path is not None:
        native_info = _copy_native_runtime_binary(Path(native_binary_path), output_path)
    elif runtime_root is not None:
        native_info = build_native_runtime_binary(runtime_root=runtime_root, output_dir=output_path)

    native_pearl_path = _write_native_pearl_wrapper(
        policy_id=policy.policy_id,
        output_dir=output_path,
        artifact_name=artifact_name,
        gate=gate,
        bit_mappings=bit_mappings,
        native_runtime=native_info,
    )

    bundle = RuntimeArtifactBundle(
        policy_id=policy.policy_id,
        gate_path=str(gate_path),
        bit_manifest_path=str(bit_manifest_path),
        native_pearl_path=str(native_pearl_path),
        wasm=WasmArtifactInfo(
            rust_source_path=str(output_path / f"{artifact_name}.rs"),
            core_wasm_path=str(wasm_result.wasm_path) if wasm_result.wasm_path else None,
            core_wasm_size_bytes=wasm_result.wasm_size_bytes,
            pearl_wasm_path=pearl_wasm_path,
            pearl_wasm_size_bytes=pearl_wasm_size_bytes,
        ),
        native_runtime=native_info,
        bit_mappings=bit_mappings,
    )
    manifest_path = output_path / f"{artifact_name}.runtime_bundle.json"
    manifest_path.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    return bundle


def build_runtime_bit_mappings(
    policy: HealthcarePolicySlice,
    gate: LogicPearlGateIR,
) -> list[RuntimeBitMapping]:
    requirement_index = {requirement.requirement_id: requirement for requirement in policy.requirements}
    mappings: list[RuntimeBitMapping] = []
    for rule in sorted(gate.rules, key=lambda item: item.bit):
        requirement_id = rule.id.removeprefix("missing_") if rule.id.startswith("missing_") else None
        requirement = requirement_index.get(requirement_id) if requirement_id else None
        mappings.append(
            RuntimeBitMapping(
                bit=rule.bit,
                rule_id=rule.id,
                requirement_id=requirement.requirement_id if requirement else requirement_id,
                question_text=requirement.question_text if requirement else None,
                cluster_id=requirement.cluster_id if requirement else None,
            )
        )
    return mappings


def build_runtime_input_from_response(response: HealthcarePolicyResponse) -> dict[str, float]:
    return {
        requirement_feature_id(question.requirement_id): 1.0 if question.status == QuestionStatus.FOUND else 0.0
        for question in response.questions
    }


def run_native_runtime_check(
    *,
    native_binary_path: str | Path,
    gate_path: str | Path,
    input_path: str | Path,
    expected_bitmask: int,
    timeout_seconds: float = 10.0,
) -> NativeRuntimeCheck:
    command = [str(native_binary_path), str(gate_path), str(input_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return NativeRuntimeCheck(
            expected_bitmask=expected_bitmask,
            parity_ok=False,
            command=" ".join(command),
            error=str(exc),
        )

    if result.returncode != 0:
        return NativeRuntimeCheck(
            expected_bitmask=expected_bitmask,
            parity_ok=False,
            command=" ".join(command),
            error=result.stderr.strip() or result.stdout.strip() or f"runtime exited {result.returncode}",
        )

    try:
        native_bitmask = int(result.stdout.strip())
    except ValueError:
        return NativeRuntimeCheck(
            expected_bitmask=expected_bitmask,
            parity_ok=False,
            command=" ".join(command),
            error=f"unable to parse runtime stdout: {result.stdout.strip()}",
        )

    return NativeRuntimeCheck(
        expected_bitmask=expected_bitmask,
        native_bitmask=native_bitmask,
        parity_ok=native_bitmask == expected_bitmask,
        command=" ".join(command),
    )


def build_native_runtime_binary(
    *,
    runtime_root: str | Path,
    output_dir: str | Path,
    binary_name: str = "pearl-runtime",
    timeout_seconds: float = 60.0,
) -> NativeRuntimeArtifactInfo:
    runtime_path = Path(runtime_root)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=runtime_path,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return NativeRuntimeArtifactInfo(
            build_succeeded=False,
            build_error=str(exc),
        )

    if result.returncode != 0:
        return NativeRuntimeArtifactInfo(
            build_succeeded=False,
            build_error=result.stderr.strip() or result.stdout.strip() or f"cargo exited {result.returncode}",
        )

    built_binary = runtime_path / "target" / "release" / binary_name
    if not built_binary.exists():
        return NativeRuntimeArtifactInfo(
            build_succeeded=False,
            build_error=f"expected binary not found at {built_binary}",
        )
    return _copy_native_runtime_binary(built_binary, output_path)


def _copy_native_runtime_binary(binary_path: Path, output_dir: Path, binary_name: str = "pearl-runtime") -> NativeRuntimeArtifactInfo:
    if not binary_path.exists():
        return NativeRuntimeArtifactInfo(
            build_succeeded=False,
            build_error=f"native runtime binary not found at {binary_path}",
        )

    target_binary = output_dir / binary_name
    shutil.copy2(binary_path, target_binary)
    target_binary.chmod(0o755)
    return NativeRuntimeArtifactInfo(
        binary_path=str(target_binary),
        binary_size_bytes=target_binary.stat().st_size,
        build_succeeded=True,
        invocation_template=f"{target_binary} <pearl.ir.json> <input.json>",
    )


def _write_native_pearl_wrapper(
    *,
    policy_id: str,
    output_dir: Path,
    artifact_name: str,
    gate: LogicPearlGateIR,
    bit_mappings: list[RuntimeBitMapping],
    native_runtime: NativeRuntimeArtifactInfo | None,
) -> Path:
    wrapper_path = output_dir / f"{artifact_name}.pearl"
    runtime_binary = Path(native_runtime.binary_path).name if native_runtime and native_runtime.binary_path else None
    feature_schema = [
        {
            "id": feature.id,
            "type": str(feature.type.value if hasattr(feature.type, "value") else feature.type),
        }
        for feature in gate.input_schema.features
    ]
    wrapper_source = _native_pearl_wrapper_source(
        policy_id=policy_id,
        artifact_name=artifact_name,
        runtime_binary_name=runtime_binary,
        feature_schema=feature_schema,
        bit_mappings=bit_mappings,
        gate_payload=gate.model_dump(mode="json"),
    )
    wrapper_path.write_text(wrapper_source, encoding="utf-8")
    wrapper_path.chmod(0o755)
    return wrapper_path


def _native_pearl_wrapper_source(
    *,
    policy_id: str,
    artifact_name: str,
    runtime_binary_name: str | None,
    feature_schema: list[dict[str, str]],
    bit_mappings: list[RuntimeBitMapping],
    gate_payload: dict,
) -> str:
    return f"""#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path

POLICY_ID = {policy_id!r}
ARTIFACT_NAME = {artifact_name!r}
RUNTIME_BINARY_NAME = {runtime_binary_name!r}
FEATURE_SCHEMA = {repr(feature_schema)}
BIT_MAPPINGS = {repr([mapping.model_dump(mode="json") for mapping in bit_mappings])}
GATE_PAYLOAD = {repr(gate_payload)}


def _load_payload(argv):
    if "--input" in argv:
        index = argv.index("--input")
        input_path = Path(argv[index + 1])
        return json.loads(input_path.read_text(encoding="utf-8"))
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            return json.loads(raw)
    return {{}}


def _coerce_value(feature_type, value):
    if feature_type in ("int", "float"):
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            return float(value)
        raise ValueError(f"feature expects numeric value, got {{type(value).__name__}}")
    if feature_type == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            lowered = value.lower()
            if lowered in ("true", "1", "yes"):
                return True
            if lowered in ("false", "0", "no"):
                return False
        raise ValueError(f"feature expects boolean value, got {{type(value).__name__}}")
    if feature_type in ("string", "enum"):
        if isinstance(value, str):
            return value
        raise ValueError(f"feature expects string value, got {{type(value).__name__}}")
    return value


def _normalize_features(payload):
    if isinstance(payload, dict) and "input" in payload and isinstance(payload["input"], dict):
        features = payload["input"].get("features", {{}})
    else:
        features = payload
    strict = True
    include_rule_hits = True
    include_counterfactuals = False
    if isinstance(payload, dict):
        options = payload.get("options", {{}})
        strict = options.get("strict", True)
        include_rule_hits = options.get("include_rule_hits", True)
        include_counterfactuals = options.get("include_counterfactuals", False)
    if not isinstance(features, dict):
        return {{
            "ok": False,
            "artifact_id": POLICY_ID,
            "error_code": "invalid_input_shape",
            "message": "input.features must be an object",
        }}

    schema = {{item["id"]: item["type"] for item in FEATURE_SCHEMA}}
    missing = [feature_id for feature_id in schema if feature_id not in features]
    unknown = sorted(set(features) - set(schema))
    normalized = {{}}
    errors = []
    for feature_id, feature_type in schema.items():
        if feature_id not in features:
            continue
        try:
            normalized[feature_id] = _coerce_value(feature_type, features[feature_id])
        except Exception as exc:
            errors.append({{"feature": feature_id, "message": str(exc)}})

    error_code = None
    if errors:
        error_code = "feature_type_error"
    elif missing:
        error_code = "missing_required_features"
    elif unknown:
        error_code = "unknown_features"

    if strict and (missing or unknown or errors):
        return {{
            "ok": False,
            "artifact_id": POLICY_ID,
            "error_code": error_code,
            "message": "input validation failed in strict mode",
            "missing_features": missing,
            "unknown_features": unknown,
            "type_errors": errors,
        }}

    for feature_id in missing:
        normalized[feature_id] = 0.0

    return {{
        "ok": True,
        "strict": strict,
        "features": normalized,
        "missing_features": missing,
        "unknown_features": unknown,
        "type_errors": errors,
        "include_rule_hits": include_rule_hits,
        "include_counterfactuals": include_counterfactuals,
    }}


def _rule_hits(bitmask):
    return [mapping for mapping in BIT_MAPPINGS if bitmask & (1 << mapping["bit"])]


def _counterfactuals(rule_hits):
    items = []
    for hit in rule_hits:
        requirement_id = hit.get("requirement_id")
        if not requirement_id:
            continue
        items.append({{
            "rule_id": hit["rule_id"],
            "bit": hit["bit"],
            "question_text": hit.get("question_text"),
            "summary": f"Set requirement__{{requirement_id}}__satisfied to 1.0 to clear bit {{hit['bit']}}.",
            "set_features": [{{
                "feature": f"requirement__{{requirement_id}}__satisfied",
                "set_to": 1.0,
                "reason": "This rule fires only when the requirement is not satisfied.",
            }}],
        }})
    return items


def _describe():
    return {{
        "ok": True,
        "artifact_id": POLICY_ID,
        "artifact_name": ARTIFACT_NAME,
        "modes": ["describe", "validate", "evaluate", "explain", "counterfactual"],
        "input_schema": FEATURE_SCHEMA,
        "bit_mappings": BIT_MAPPINGS,
    }}


def _evaluate_expression(expression, features):
    if "feature" in expression:
        left = features.get(expression["feature"])
        right = expression["value"]
        op = expression["op"]
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == "in":
            return left in right
        if op == "not_in":
            return left not in right
        raise ValueError(f"unsupported operator: {{op}}")
    if "all" in expression:
        return all(_evaluate_expression(item, features) for item in expression["all"])
    if "any" in expression:
        return any(_evaluate_expression(item, features) for item in expression["any"])
    if "not" in expression:
        return not _evaluate_expression(expression["not"], features)
    raise ValueError("unsupported expression shape")


def _evaluate_with_embedded_ir(normalized):
    bitmask = 0
    for rule in GATE_PAYLOAD["rules"]:
        if _evaluate_expression(rule["deny_when"], normalized["features"]):
            bitmask |= 1 << rule["bit"]
    hits = _rule_hits(bitmask)
    payload = {{
        "ok": True,
        "artifact_id": POLICY_ID,
        "bitmask": bitmask,
        "allowed": bitmask == 0,
        "missing_features": normalized["missing_features"],
        "unknown_features": normalized["unknown_features"],
        "type_errors": normalized["type_errors"],
    }}
    if normalized.get("include_rule_hits", True):
        payload["rule_hits"] = hits
    payload["evaluator"] = "embedded_python_fallback"
    return payload


def _evaluate(normalized):
    gate_path = Path(__file__).with_name(f"{{ARTIFACT_NAME}}.ir.json")
    runtime_path = Path(__file__).with_name(RUNTIME_BINARY_NAME) if RUNTIME_BINARY_NAME else None
    if runtime_path is None or not runtime_path.exists():
        return _evaluate_with_embedded_ir(normalized)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(normalized["features"], handle)
        temp_path = Path(handle.name)
    try:
        result = subprocess.run(
            [str(runtime_path), str(gate_path), str(temp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        temp_path.unlink(missing_ok=True)
    if result.returncode != 0:
        return {{
            "ok": False,
            "artifact_id": POLICY_ID,
            "error_code": "runtime_error",
            "message": result.stderr.strip() or result.stdout.strip() or f"runtime exited {{result.returncode}}",
        }}
    bitmask = int(result.stdout.strip())
    hits = _rule_hits(bitmask)
    payload = {{
        "ok": True,
        "artifact_id": POLICY_ID,
        "bitmask": bitmask,
        "allowed": bitmask == 0,
        "missing_features": normalized["missing_features"],
        "unknown_features": normalized["unknown_features"],
        "type_errors": normalized["type_errors"],
    }}
    if normalized.get("include_rule_hits", True):
        payload["rule_hits"] = hits
    payload["evaluator"] = "bundled_native_runtime"
    return payload


def _explain(evaluation):
    hits = evaluation.get("rule_hits", [])
    return {{
        **evaluation,
        "explanation": {{
            "fired_rule_count": len(hits),
            "rules": [
                {{
                    "rule_id": hit["rule_id"],
                    "bit": hit["bit"],
                    "question_text": hit.get("question_text"),
                    "cluster_id": hit.get("cluster_id"),
                    "why": f"Bit {{hit['bit']}} fired because the required feature for {{hit.get('requirement_id') or hit['rule_id']}} was not satisfied.",
                }}
                for hit in hits
            ],
        }},
    }}


def main(argv):
    mode = argv[1] if len(argv) > 1 and not argv[1].startswith("--") else "evaluate"
    if mode == "describe":
        print(json.dumps(_describe(), indent=2))
        return 0
    payload = _load_payload(argv[1:])
    normalized = _normalize_features(payload)
    if mode == "validate":
        print(json.dumps(normalized, indent=2))
        return 0 if normalized.get("ok") else 1
    if not normalized.get("ok"):
        print(json.dumps(normalized, indent=2))
        return 1
    evaluation = _evaluate(normalized)
    if mode == "explain" and evaluation.get("ok"):
        evaluation = _explain(evaluation)
    if mode == "counterfactual" and evaluation.get("ok"):
        hits = evaluation.get("rule_hits", _rule_hits(evaluation.get("bitmask", 0)))
        evaluation["counterfactuals"] = _counterfactuals(hits)
        evaluation["recommended_action"] = (
            "clear_all_fired_bits" if hits else "no_action_needed"
        )
    print(json.dumps(evaluation, indent=2))
    return 0 if evaluation.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
"""
