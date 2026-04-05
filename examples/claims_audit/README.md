# Claims Audit Demo

This demo now has an explicit split between reusable LogicPearl logic and demo-only oracle logic.

Layout:
- `oracle/`
  - mock adjudication engine
  - synthetic claims generation
  - planted bugs and rule manifest
  - generated adjudicated dataset
- `../../../private/logicpearl/benchmarks/claims_audit/`
  - reverse-engineering harness
  - audit reports
  - circuit compilation experiments

The demo goal remains the same:
- generate realistic claims,
- adjudicate them with a known oracle,
- run LogicPearl over the observed behavior,
- measure how well LogicPearl reconstructs the oracle rules and bugs.

Why this split is better:
- the oracle is clearly not part of the general LogicPearl engine,
- the benchmark harness is clearly not the domain adapter,
- reusable claims observation now lives in the private applied layer rather than the public proof layer.

Current source of truth:
- oracle generation: [oracle/generate_claims.py](/Users/missingno/Documents/LogicPearl/logicpearl/demos/claims_audit/oracle/generate_claims.py)
- oracle rules: [oracle/engine.py](/Users/missingno/Documents/LogicPearl/logicpearl/demos/claims_audit/oracle/engine.py)
- reusable claims adapter: private applied claims observer
- benchmark harness: [build_and_audit.py](/Users/missingno/Documents/LogicPearl/private/logicpearl/benchmarks/claims_audit/build_and_audit.py)
