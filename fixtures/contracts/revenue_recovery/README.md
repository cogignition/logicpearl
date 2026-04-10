## Revenue Recovery Contract Fixtures

This fixture lane is a small frozen conformance contract derived from the
public `healthcare_demo` revenue recovery workflow.

Purpose:
- protect `logicpearl` solver and runtime changes against regressions that
  would break representative revenue routing and readiness artifacts
- keep the boundary clean by freezing only artifact bundles, normalized
  feature-map inputs, and expected engine-facing outputs
- avoid any runtime dependency on `healthcare_demo` account packets, observers,
  or frontend code

The fixture names here are intentionally generic. They are derived from
representative synthetic recovery workflows rather than customer-branded cases.

What is intentionally included:
- six representative revenue recovery artifacts
- normalized feature-map scenarios for routing and readiness
- expected bitmask outputs and fired rule ids
- earlier/current pearl IR pairs for semantic diff checks on readiness logic

What is intentionally excluded:
- raw recovery account packets
- observer plugins
- UI bundles
- generated website exports

The expected outputs here should be treated as a contract for the public
LogicPearl runtime and CLI surfaces, not as a benchmark lane.
