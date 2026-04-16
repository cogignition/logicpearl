# Python Runtime

Use the `logicpearl` Python package when a Python service needs to load a
LogicPearl artifact once and evaluate requests in-process.

```python
from logicpearl import LogicPearlEngine

engine = LogicPearlEngine.from_path("/srv/artifacts/access-policy")

result = engine.evaluate({
    "clearance_ok": False,
    "mfa_enabled": True,
})

print(result["decision_kind"])
print(result["allow"])
```

`evaluate()` returns the runtime payload directly. For gate and action
artifacts, that payload is the same schema-shaped result emitted by
`logicpearl run --json`. `evaluate_batch()` accepts a list of JSON-compatible
Python inputs and returns a list of runtime payloads.

Use `run()`, `run_single()`, or `run_batch()` when a caller needs the full engine
envelope with the artifact kind included.

The package is a thin PyO3 bridge over `logicpearl-engine`; it does not shell
out to the CLI and does not reimplement rule semantics in Python. Pipeline
execution still follows the same plugin trust boundary as the Rust engine:
pipeline manifests can execute local process plugins, so only load pipelines
from sources you trust.
