# `logicpearl`

Official Python bindings for `logicpearl-engine`.

Use this package when:
- Python code needs to execute a pearl artifact or pipeline directly
- you want a real bridge to the Rust execution surface
- you do not want to shell out to the CLI for every request

Do not use it as a reason to bake observers into pearls.
The intended split is still:
- observer/plugin: messy input interpretation
- pearl: deterministic policy artifact
- verify/response: operational interpretation

## Example

```python
from logicpearl import LogicPearlEngine

engine = LogicPearlEngine.from_path("examples/pipelines/observer_membership_verify/pipeline.json")
result = engine.run({
    "age": 34,
    "member": True,
    "country": "US",
})

print(result["mode"])
print(result["kind"])
```

## Scope

This package exposes local execution through `logicpearl-engine`.

It is:
- not a service client yet
- not a reimplementation of runtime semantics in Python
- not a wrapper around `logicpearl` CLI subprocess calls
