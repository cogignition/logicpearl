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
