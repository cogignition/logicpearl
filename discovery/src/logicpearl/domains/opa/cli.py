from __future__ import annotations

import argparse

from .parser import infer_rego_policy_metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect a Rego policy through LogicPearl's OPA adapter.")
    parser.add_argument("policy", help="Path to a .rego policy file")
    args = parser.parse_args()

    metadata = infer_rego_policy_metadata(args.policy)
    print(f"Policy:    {metadata.source_path}")
    print(f"Package:   {metadata.package}")
    print(f"Rules:     {', '.join(metadata.rule_names) if metadata.rule_names else '(none)'}")
    print(f"Defaults:  {', '.join(metadata.default_rules) if metadata.default_rules else '(none)'}")
