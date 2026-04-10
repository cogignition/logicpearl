# Security Policy

If you believe you have found a security issue in LogicPearl, report it privately first rather than opening a public issue.

Private disclosure contact:
- `ken@logicpearl.com`
- subject line: `LogicPearl security report`

Please include:
- the affected component
- reproduction steps
- the impact
- any suggested mitigation or context that helps validate the issue

LogicPearl will acknowledge reports, validate the issue, and coordinate disclosure timing before publishing a fix or advisory.

For general bugs, feature requests, or documentation issues, use the issue tracker.

This project contains real artifacts, runtimes, and demos, but it is not presented as a hardened enterprise deployment package.

Security-sensitive areas to report responsibly include:
- runtime evaluation behavior
- artifact loading/validation issues
- malformed input handling
- observer execution behavior
- WASM/runtime generation paths

## Plugin And Pipeline Execution

LogicPearl process plugins are trusted local extensions, not a sandbox for untrusted third-party code.

Plugin manifests declare an `entrypoint`, and these surfaces execute that entrypoint as a local process:
- `logicpearl plugin run`
- `logicpearl plugin validate` when a smoke input is provided
- `logicpearl build --trace-plugin-manifest ...`
- `logicpearl build --enricher-plugin-manifest ...`
- `logicpearl observer run --plugin-manifest ...`
- `logicpearl verify --plugin-manifest ...`
- plugin-backed `logicpearl pipeline run` and `logicpearl pipeline trace`
- plugin-backed `logicpearl benchmark run`, `benchmark observe`, and `benchmark learn`

Do not run plugin or pipeline manifests from sources you do not trust. LogicPearl keeps normal trusted-local plugin workflows usable by default, but it rejects risky entrypoint shapes unless the caller explicitly opts into those relaxations.

The default process-plugin policy is intentionally conservative:
- missing `timeout_ms` uses a 30 second timeout
- `timeout_ms: 0` disables timeouts only when the caller explicitly allows no-timeout execution
- manifest-relative scripts are allowed
- known interpreters such as `python3 plugin.py` are allowed when the script is manifest-relative
- arbitrary bare PATH entrypoints and absolute entrypoint paths require explicit trusted-policy opt-ins such as `--allow-plugin-path-lookup` or `--allow-absolute-plugin-entrypoint`
