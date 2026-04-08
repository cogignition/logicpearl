# logicpearl-engine

`logicpearl-engine` is the library-level execution facade for LogicPearl.

Use it when:

- you are building an app backend or execution service
- you want to load a pearl or pipeline once and execute it repeatedly
- your workflow uses plugins or other server-side adapters

Do not use it for:

- browser-only evaluation
- shell-first human workflows

Those surfaces are:

- `@logicpearl/browser` for browser-safe execution
- `logicpearl` for the public CLI

## Example

```rust
use logicpearl_engine::{EngineSingleExecution, LogicPearlEngine};
use serde_json::json;

let engine = LogicPearlEngine::from_artifact_path("examples/getting_started/output")?;
let result = engine.run_single_json(&json!({
    "action": "read",
    "member_age": 29,
    "country": "US"
}))?;

match result {
    EngineSingleExecution::Artifact(output) => {
        println!("allow={}", output.evaluation.allow);
        println!("bitmask={}", output.evaluation.bitmask);
    }
    EngineSingleExecution::Pipeline(_) => unreachable!(),
}
# Ok::<(), logicpearl_core::LogicPearlError>(())
```
