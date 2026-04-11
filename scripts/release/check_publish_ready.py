#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
import tomllib
from collections import defaultdict, deque
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_MANIFEST = REPO_ROOT / "Cargo.toml"
BROWSER_PACKAGE_JSON = REPO_ROOT / "packages" / "logicpearl-browser" / "package.json"
PYTHON_PYPROJECT = REPO_ROOT / "reserved-python" / "logicpearl" / "pyproject.toml"
PYTHON_MANIFEST = REPO_ROOT / "reserved-python" / "logicpearl" / "Cargo.toml"


def load_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def manifest_for(member: str) -> tuple[Path, dict]:
    path = REPO_ROOT / member / "Cargo.toml"
    return path, load_toml(path)


def dependency_spec(manifest: dict, dependency_name: str):
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        deps = manifest.get(section, {})
        if dependency_name in deps:
            return section, deps[dependency_name]
    return None, None


def inherits_workspace(package: dict, field: str) -> bool:
    value = package.get(field)
    return isinstance(value, dict) and value.get("workspace") is True


def main() -> int:
    workspace = load_toml(WORKSPACE_MANIFEST)
    members: list[str] = workspace["workspace"]["members"]
    workspace_package = workspace.get("workspace", {}).get("package", {})
    workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
    workspace_version = workspace_package.get("version")

    manifests: dict[str, tuple[Path, dict]] = {}
    crate_names: dict[str, str] = {}
    for member in members:
        path, manifest = manifest_for(member)
        manifests[member] = (path, manifest)
        crate_names[member] = manifest["package"]["name"]

    internal_names = set(crate_names.values())
    errors: list[str] = []
    graph: dict[str, set[str]] = defaultdict(set)
    indegree: dict[str, int] = {name: 0 for name in internal_names}

    if not workspace_version:
        errors.append(f"{WORKSPACE_MANIFEST}: missing workspace.package.version")
    else:
        for dep_name in sorted(internal_names):
            ws_spec = workspace_dependencies.get(dep_name)
            if isinstance(ws_spec, dict) and ws_spec.get("version") != workspace_version:
                errors.append(
                    f"{WORKSPACE_MANIFEST}: workspace dependency `{dep_name}` version {ws_spec.get('version')!r} must match workspace version {workspace_version!r}"
                )

        browser_version = json.loads(BROWSER_PACKAGE_JSON.read_text()).get("version")
        if browser_version != workspace_version:
            errors.append(
                f"{BROWSER_PACKAGE_JSON}: package version {browser_version!r} must match workspace version {workspace_version!r}"
            )

        python_project = load_toml(PYTHON_PYPROJECT).get("project", {})
        if python_project.get("version") != workspace_version:
            errors.append(
                f"{PYTHON_PYPROJECT}: project.version {python_project.get('version')!r} must match workspace version {workspace_version!r}"
            )

        python_package = load_toml(PYTHON_MANIFEST).get("package", {})
        if python_package.get("version") != workspace_version:
            errors.append(
                f"{PYTHON_MANIFEST}: package.version {python_package.get('version')!r} must match workspace version {workspace_version!r}"
            )

    for member, (path, manifest) in manifests.items():
        package = manifest.get("package", {})
        crate_name = package.get("name", member)
        for field in ("version", "edition", "license"):
            if field not in package:
                errors.append(f"{path}: missing package field `{field}`")
        if not package.get("description"):
            errors.append(f"{path}: missing package.description")
        if not (inherits_workspace(package, "homepage") or package.get("homepage") or workspace_package.get("homepage")):
            errors.append(f"{path}: missing package.homepage")
        if not (
            inherits_workspace(package, "repository") or package.get("repository") or workspace_package.get("repository")
        ):
            errors.append(f"{path}: missing package.repository")

        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = manifest.get(section, {})
            for dep_name, spec in deps.items():
                if dep_name not in internal_names:
                    continue
                if dep_name == crate_name:
                    continue
                if isinstance(spec, str):
                    errors.append(f"{path}: internal dependency `{dep_name}` in [{section}] must use a table with version metadata")
                    continue
                if spec.get("workspace") is True:
                    ws_spec = workspace_dependencies.get(dep_name)
                    if not isinstance(ws_spec, dict):
                        errors.append(f"{WORKSPACE_MANIFEST}: missing workspace dependency entry for `{dep_name}`")
                        continue
                    if "path" not in ws_spec or "version" not in ws_spec:
                        errors.append(
                            f"{WORKSPACE_MANIFEST}: workspace dependency `{dep_name}` must include both `path` and `version`"
                        )
                else:
                    if "path" not in spec or "version" not in spec:
                        errors.append(
                            f"{path}: internal dependency `{dep_name}` in [{section}] must include both `path` and `version` or use `.workspace = true`"
                        )

                if section == "dependencies":
                    graph[dep_name].add(crate_name)
                    indegree[crate_name] += 1

    queue = deque(sorted(name for name, degree in indegree.items() if degree == 0))
    publish_order: list[str] = []
    while queue:
        crate = queue.popleft()
        publish_order.append(crate)
        for dependent in sorted(graph.get(crate, ())):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)

    if len(publish_order) != len(internal_names):
        errors.append("could not derive a full publish order from internal dependency graph")

    if errors:
        print("publish readiness check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("publish readiness check passed")
    print("publish order:")
    for crate in publish_order:
        print(f"  - {crate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
