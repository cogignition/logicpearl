# Claims Audit Example

This example keeps a small synthetic claims oracle in the public repo.

Contents:
- `oracle/generate_claims.py`
  - emits synthetic claims and adjudication inputs
- `oracle/engine.py`
  - mock adjudication logic used as the example oracle

What this example proves:
- LogicPearl can be applied to a bounded claims-style decision surface
- oracle behavior can be generated reproducibly from a local script
- public example material can stay separate from private reconstruction workflows

What this example does not include:
- the private reverse-engineering harness
- private audit workflows
- customer or domain deployment logic

If you want a public-first walkthrough, prefer the getting-started example and the small demo datasets under [examples/demos](../demos).
