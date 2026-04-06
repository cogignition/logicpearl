#!/usr/bin/env python3

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RESERVED_ROOT = REPO_ROOT / "reserved-crates"
REQUIRED_FIELDS = ("name", "version", "edition", "license", "description", "homepage", "repository")


def load_manifest(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    manifests = sorted(RESERVED_ROOT.glob("*/Cargo.toml"))
    if not manifests:
        print("no reserved crates found", file=sys.stderr)
        return 1

    errors: list[str] = []
    for manifest_path in manifests:
        manifest = load_manifest(manifest_path)
        package = manifest.get("package", {})
        for field in REQUIRED_FIELDS:
            if not package.get(field):
                errors.append(f"{manifest_path}: missing package.{field}")
        lib_path = manifest_path.parent / "src" / "lib.rs"
        if not lib_path.exists():
            errors.append(f"{manifest_path}: missing src/lib.rs")

    if errors:
        print("reserved crate readiness check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("reserved crate readiness check passed")
    for manifest_path in manifests:
        package = load_manifest(manifest_path)["package"]
        print(f"  - {package['name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
