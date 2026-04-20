## Healthcare Prior Auth Contract Fixtures

This fixture lane is a small frozen private conformance contract derived from
the healthcare demo corpus.

Purpose:
- protect `logicpearl` solver and runtime changes against regressions that
  would break representative prior-auth artifact behavior
- keep the boundary clean by freezing only artifact bundles, normalized
  feature-map inputs, and expected engine-facing outputs
- avoid any runtime dependency on `healthcare_demo`, PDFs, observers, or UI

The fixture names here are intentionally generic. They are derived from public
policy artifacts, but they are presented as neutral contract samples rather
than customer-branded examples.

What is intentionally included:
- four representative BCBSMA prior-auth policy artifacts
- frozen feature-map scenarios for each policy
- expected bitmask outputs and missing rule ids
- earlier/current pearl IR pairs for semantic diff checks

What is intentionally excluded:
- raw intake packets
- healthcare observer plugins
- review workflows
- PDFs or section extraction assets

The expected outputs here should be treated as a private domain regression
contract, not as part of the generic public LogicPearl runtime or CLI surface.
