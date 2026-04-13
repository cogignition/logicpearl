# HN Readiness Fixes — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers-extended-cc:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 40 issues identified by the 6-persona HN review audit before public launch.

**Architecture:** Changes span documentation (README, CONTRIBUTING, CHANGELOG, new files), code fixes (error handling, security, API types), CI configuration, and project governance files. No architectural rewrites — these are targeted fixes.

**Tech Stack:** Rust, shell (install.sh), GitHub Actions YAML, Markdown

---

### Task 1: Fix ReceiptSigningKeyFile security issue

**Files:**
- Modify: `crates/logicpearl-conformance/src/lib.rs:51-56`
- Modify: `crates/logicpearl-conformance/Cargo.toml`

**Context:** The `ReceiptSigningKeyFile` struct serializes `secret_key_hex` as plain text. The `zeroize` crate is already a transitive dep via `ed25519-dalek`. Wire it up.

**Step 1: Add `zeroize` to conformance crate deps**

In `crates/logicpearl-conformance/Cargo.toml`, add:
```toml
zeroize = { version = "1", features = ["derive"] }
```

**Step 2: Fix the struct**

In `crates/logicpearl-conformance/src/lib.rs`, change:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSigningKeyFile {
    pub algorithm: String,
    pub secret_key_hex: String,
    pub public_key_hex: String,
}
```
to:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ReceiptSigningKeyFile {
    pub algorithm: String,
    #[serde(skip_serializing)]
    pub secret_key_hex: String,
    pub public_key_hex: String,
}
```

**Step 3: Verify build**

```bash
cargo build -p logicpearl-conformance
cargo test -p logicpearl-conformance
```

**Step 4: Commit**
```bash
git add crates/logicpearl-conformance/
git commit -m "fix: prevent secret key serialization and add zeroize to ReceiptSigningKeyFile"
```

---

### Task 2: Fix production expect() calls in discovery crate

**Files:**
- Modify: `crates/logicpearl-discovery/src/lib.rs:284-286`
- Modify: `crates/logicpearl-discovery/src/lib.rs:735-738`
- Modify: `crates/logicpearl-discovery/src/features.rs:162-164`

**Context:** Three `expect()` calls in non-test production code can panic. Replace with proper error handling.

**Step 1: Fix CandidateRule::signature()**

In `crates/logicpearl-discovery/src/lib.rs:283-286`, change:
```rust
fn signature(&self) -> String {
    serde_json::to_string(&self.expression).expect("candidate rule signature serialization")
}
```
to:
```rust
fn signature(&self) -> Result<String> {
    serde_json::to_string(&self.expression).map_err(|e| {
        LogicPearlError::message(format!("candidate rule signature serialization failed: {e}"))
    })
}
```

Then fix all callers of `.signature()` to propagate the `?` operator.

**Step 2: Fix target initialized expect()**

In `crates/logicpearl-discovery/src/lib.rs:735-738`, change:
```rust
per_target_rows
    .get_mut(target)
    .expect("target initialized")
```
to:
```rust
per_target_rows
    .get_mut(target)
    .ok_or_else(|| LogicPearlError::message(format!("target {target:?} not initialized")))?
```

**Step 3: Fix finite interaction value expect()**

In `crates/logicpearl-discovery/src/features.rs:162-164`, change:
```rust
Value::Number(
    Number::from_f64(values[row_index]).expect("finite interaction value"),
)
```
to:
```rust
Value::Number(
    Number::from_f64(values[row_index]).ok_or_else(|| {
        LogicPearlError::message(format!(
            "derived feature produced non-finite value at row {row_index}"
        ))
    })?,
)
```

**Step 4: Verify**
```bash
cargo build -p logicpearl-discovery
cargo test -p logicpearl-discovery
```

**Step 5: Commit**
```bash
git add crates/logicpearl-discovery/
git commit -m "fix: replace expect() calls with proper Result propagation in discovery"
```

---

### Task 3: Replace stringly-typed fields with enums in IR crate

**Files:**
- Modify: `crates/logicpearl-ir/src/lib.rs`

**Context:** `EvaluationConfig.combine` and `LogicPearlGateIr.gate_type` are `String` fields validated by string comparison. Replace with enums.

**Step 1: Add enum types**

Before the `EvaluationConfig` struct, add:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CombineStrategy {
    BitwiseOr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GateType {
    BitmaskGate,
}
```

**Step 2: Update structs**

Change `gate_type: String` to `gate_type: GateType` in `LogicPearlGateIr`.
Change `combine: String` to `combine: CombineStrategy` in `EvaluationConfig`.

**Step 3: Update validate()**

Remove the string comparison checks for `gate_type` and `combine` in `validate()` (lines 284-295) — they're now enforced by deserialization.

**Step 4: Fix all downstream usages**

Search for `.gate_type` and `.combine` references and update comparisons to use the enum variants.

**Step 5: Verify**
```bash
cargo build --workspace
cargo test --workspace
```

**Step 6: Commit**
```bash
git add crates/
git commit -m "refactor: replace stringly-typed gate_type and combine with proper enums"
```

---

### Task 4: Fix plugin crate — replace raw FFI with libc, fix magic constant

**Files:**
- Modify: `crates/logicpearl-plugin/src/lib.rs:26-36` (FFI declarations)
- Modify: `crates/logicpearl-plugin/src/lib.rs:605` (magic constant)
- Modify: `crates/logicpearl-plugin/Cargo.toml`

**Step 1: Add libc dependency**

In `crates/logicpearl-plugin/Cargo.toml`, add:
```toml
[target.'cfg(unix)'.dependencies]
libc = "0.2"
```

**Step 2: Replace raw FFI declarations**

In `crates/logicpearl-plugin/src/lib.rs`, remove lines 26-36:
```rust
#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn getpgid(pid: i32) -> i32;
    fn getpgrp() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}
```

Replace with:
```rust
#[cfg(unix)]
use libc::{getpgid, getpgrp, kill, SIGTERM, SIGKILL};
```

Then update all call sites — `getpgid`, `getpgrp`, `kill` calls may need minor type adjustments (`pid_t` = `i32` on most platforms, but verify).

**Step 3: Fix magic constant 26**

In `crates/logicpearl-plugin/src/lib.rs:604-605`, change:
```rust
fn is_executable_file_busy(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(26)
}
```
to:
```rust
fn is_executable_file_busy(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ETXTBSY)
}
```

**Step 4: Verify**
```bash
cargo build -p logicpearl-plugin
cargo test -p logicpearl-plugin
```

**Step 5: Commit**
```bash
git add crates/logicpearl-plugin/
git commit -m "refactor: replace raw FFI with libc crate, use ETXTBSY constant"
```

---

### Task 5: Add unit tests for logicpearl-ir and logicpearl-runtime

**Files:**
- Modify: `crates/logicpearl-ir/src/lib.rs` (add `#[cfg(test)] mod tests`)
- Modify: `crates/logicpearl-runtime/src/lib.rs` (add `#[cfg(test)] mod tests`)

**Context:** Both crates have zero unit tests. The IR crate has complex validation logic; the runtime has the evaluation hot path and surprising scalar parsing.

**Step 1: Add IR validation tests**

Add a `#[cfg(test)]` module at the bottom of `crates/logicpearl-ir/src/lib.rs` with tests:
- `valid_minimal_gate_passes_validation` — construct a minimal valid gate IR, assert `validate()` is Ok
- `rejects_empty_gate_id` — assert `validate()` returns error for empty gate_id
- `rejects_empty_rules` — assert error for empty rules vec
- `rejects_empty_features` — assert error for empty features
- `rejects_duplicate_rule_ids` — two rules with same id
- `rejects_duplicate_rule_bits` — two rules with same bit
- `roundtrip_serialization` — serialize then deserialize a gate IR, assert equality

**Step 2: Add runtime evaluation tests**

Add tests to `crates/logicpearl-runtime/src/lib.rs`:
- `evaluate_gate_allows_when_no_rules_match` — construct gate, pass input that matches nothing, assert `allow: true`
- `evaluate_gate_denies_when_rule_matches` — pass input that triggers a rule, assert `allow: false`
- `parse_input_payload_single_object` — `{"age": 25}` parses to vec of 1
- `parse_input_payload_array` — `[{"age": 25}, {"age": 17}]` parses to vec of 2
- `normalize_scalar_currency_prefix` — test that `"$1000"` becomes `1000`
- `normalize_scalar_accounting_negative` — test that `"(500)"` becomes `-500`
- `gate_result_fields_match` — verify `artifact_id`, `policy_id`, `gate_id` are all `gate.gate_id`

**Step 3: Verify**
```bash
cargo test -p logicpearl-ir
cargo test -p logicpearl-runtime
```

**Step 4: Commit**
```bash
git add crates/logicpearl-ir/ crates/logicpearl-runtime/
git commit -m "test: add unit tests for IR validation and runtime evaluation"
```

---

### Task 6: README improvements

**Files:**
- Modify: `README.md`

**Context:** Multiple documentation issues from the RTFM and Business Strategist reviews.

**Step 1: Move terminology gate after quickstart**

Move line 43 (`New here? Read [Terminology](./TERMINOLOGY.md) first.`) to after the quickstart code block (after line 54). The quickstart should not be gated by a terminology prerequisite.

**Step 2: Clarify quickstart vs quickstart build**

At lines 101-105, change to clearly explain these are alternatives:
```markdown
Install the public CLI once, then explore:

```bash
# Install with the verified release bundle flow in docs/install.md, then:
logicpearl quickstart          # interactive menu of all quickstart paths
logicpearl quickstart build    # jump directly to the build walkthrough
```

Either command works — `quickstart` shows a menu; `quickstart build` skips to the build path.
```

**Step 3: Delete or fill Auth Demo stub**

At lines 762-764, the Auth Demo section is a stub. Replace with a reference to the fixture:
```markdown
### Auth Demo

A compact artifact-first demo for learning the pearl format and runtime shape.

See:
- [fixtures/ir/valid/auth-demo-v1.json](./fixtures/ir/valid/auth-demo-v1.json)

```bash
logicpearl inspect fixtures/ir/valid/auth-demo-v1.json
logicpearl run fixtures/ir/valid/auth-demo-v1.json '{"role": "viewer", "resource": "doc"}'
```
```

**Step 4: Add solver architecture note**

After the "Start Here" section, add a brief note explaining the solver dependency:
```markdown
> **How discovery works:** `logicpearl build` uses an SMT solver (z3, bundled with the installer) to discover exact decision rules from your training data. A pure-Rust MIP fallback is available via `LOGICPEARL_SOLVER_BACKEND=mip`. The runtime evaluator is pure Rust with no external dependencies.
```

**Step 5: Add sustainability / intentions statement**

Before the "Repository Layout" section, add:
```markdown
## Project Status

LogicPearl is a single-maintainer project at version 0.1.x. The core engine is fully open-source under MIT. The fixtures include conformance contracts derived from real domain work (healthcare prior authorization, revenue recovery) — these domains motivate the engine design but the engine itself is domain-agnostic.

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).
```

**Step 6: Commit**
```bash
git add README.md
git commit -m "docs: improve README — move terminology gate, clarify quickstart, add solver note, add project status"
```

---

### Task 7: CONTRIBUTING.md, CHANGELOG, and governance files

**Files:**
- Modify: `CONTRIBUTING.md`
- Modify: `CHANGELOG.md`
- Create: `CODE_OF_CONDUCT.md`
- Modify: `docs/install.md:24`

**Step 1: Add prerequisites to CONTRIBUTING.md**

Add a "Prerequisites" section at the top of the Local Development section (before the git hooks line):
```markdown
### Prerequisites

- Rust stable (latest; no MSRV is declared yet)
- z3 SMT solver on PATH (`apt install z3` or `brew install z3`)
- Node.js >= 18 (for browser runtime tests)
- Git

### Local Development
```

**Step 2: Add DCO section to CONTRIBUTING.md**

At the end of CONTRIBUTING.md, add:
```markdown
## Developer Certificate of Origin

By submitting a pull request, you certify the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means you wrote the code or have the right to submit it, and you agree it can be distributed under the project's MIT license.
```

**Step 3: Backfill CHANGELOG entries**

Add entries for 0.1.3, 0.1.4, 0.1.5 based on git log. At minimum, collapse the Unreleased section into a 0.1.5 entry with the current date.

**Step 4: Add CODE_OF_CONDUCT.md**

Create a standard Contributor Covenant Code of Conduct (v2.1).

**Step 5: Fix PATH instructions in docs/install.md**

Change line 24 from:
```
If `~/.local/bin` is not already on your `PATH`, add it and open a new shell.
```
to:
```markdown
If `~/.local/bin` is not already on your `PATH`, add it:

```bash
# For zsh (macOS default):
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

# For bash:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```
```

**Step 6: Fix PATH instruction in install.sh**

At line 256, change:
```sh
printf 'Add %s to PATH, then run: logicpearl quickstart\n' "$bin_dir"
```
to:
```sh
printf 'Add %s to PATH:\n' "$bin_dir"
printf '  echo '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc && source ~/.zshrc\n' "$bin_dir"
printf 'Then run: logicpearl quickstart\n'
```

**Step 7: Commit**
```bash
git add CONTRIBUTING.md CHANGELOG.md CODE_OF_CONDUCT.md docs/install.md install.sh
git commit -m "docs: add prerequisites, DCO, code of conduct, backfill changelog, fix PATH instructions"
```

---

### Task 8: Add MSRV, cargo-deny, and NOTICES file

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `deny.toml`
- Create: `NOTICES.md`
- Modify: `.github/workflows/test.yml`

**Step 1: Declare MSRV in workspace Cargo.toml**

Add to `[workspace.package]`:
```toml
rust-version = "1.75"
```
(Or whatever the actual MSRV is — test by checking the oldest Rust version the code compiles on.)

**Step 2: Create deny.toml**

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
vulnerability = "deny"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Unicode-DFS-2016"]

[[licenses.clarify]]
name = "r-efi"
expression = "MIT"
license-files = [{ path = "LICENSE-MIT", hash = 0 }]

[bans]
multiple-versions = "warn"
```

**Step 3: Create NOTICES.md**

```markdown
# Third-Party Notices

LogicPearl includes dependencies under the following licenses. All are permissive.

## License Elections

- **r-efi**: Licensed under MIT OR Apache-2.0 OR LGPL-2.1-or-later. This project elects **MIT**.

## Notable Dependencies

- **unsafe-libyaml** (via `serde_yaml`): MIT-licensed pure-Rust port of libyaml by dtolnay. Despite the name, this is not an FFI binding to system libyaml.
- **ed25519-dalek** and curve dependencies: BSD-3-Clause. Used for decision receipt signing in `logicpearl-conformance`.

Run `cargo deny check licenses` to audit the full dependency tree.
```

**Step 4: Add cargo-deny to CI**

In `.github/workflows/test.yml`, add a step before the test step:
```yaml
- name: Install cargo-deny
  run: cargo install cargo-deny --locked
- name: Check licenses
  run: cargo deny check licenses
```

**Step 5: Commit**
```bash
git add Cargo.toml deny.toml NOTICES.md .github/workflows/test.yml
git commit -m "chore: add MSRV, cargo-deny license checking, and NOTICES file"
```

---

### Task 9: Add ROADMAP.md and browser package fixes

**Files:**
- Create: `ROADMAP.md`
- Modify: `packages/logicpearl-browser/README.md`
- Modify: `packages/logicpearl-browser/package.json`

**Step 1: Create ROADMAP.md**

```markdown
# Roadmap

This is a living document. Items are not commitments — they reflect current direction.

## Near-Term (0.2.x)

- [ ] Criterion benchmarks for runtime evaluation latency
- [ ] Garden Actions demo (multi-action artifact walkthrough)
- [ ] WAF demo (custom observer plugins, raw-request classification)
- [ ] `logicpearl explain` command for counterfactual output
- [ ] API documentation pass (`#![deny(missing_docs)]` on published crates)

## Medium-Term

- [ ] `@logicpearl/browser` published to npm
- [ ] `logicpearl` Python package published to PyPI
- [ ] Feature-gated conformance (crypto deps optional)
- [ ] Plugin-based benchmark dataset adapters (replace hardcoded parsers)

## Long-Term

- [ ] Stable Pearl IR v2 schema
- [ ] `logicpearl-wasm` crate for Wasm-first deployments
- [ ] Hosted evaluation API (opt-in, no telemetry in the open-source CLI)
```

**Step 2: Fix browser README**

Add installation instructions at the top of `packages/logicpearl-browser/README.md`:
```markdown
> **Note:** This package is not yet published to npm. To use it, copy the `packages/logicpearl-browser` directory into your project or reference it as a local dependency.
```

**Step 3: Add publishConfig or private flag to package.json**

Add `"private": true` to `packages/logicpearl-browser/package.json` until it's ready for npm.

**Step 4: Commit**
```bash
git add ROADMAP.md packages/logicpearl-browser/
git commit -m "docs: add roadmap, clarify browser package is not yet on npm"
```

---

### Task 10: Demo directory READMEs and getting-started improvements

**Files:**
- Create: `examples/demos/loan_approval/README.md`
- Create: `examples/demos/content_moderation/README.md`
- Modify: `examples/getting_started/decision_traces.csv` (or add a better example)

**Step 1: Add loan_approval README**

```markdown
# Loan Approval Demo

Demonstrates multi-feature decision traces in JSONL format.

## Run

```bash
logicpearl build examples/demos/loan_approval/traces.jsonl --output-dir /tmp/loan-demo
logicpearl inspect /tmp/loan-demo
```
```

**Step 2: Add content_moderation README**

```markdown
# Content Moderation Demo

Demonstrates nested JSON input traces for content moderation decisions.

## Run

```bash
logicpearl build examples/demos/content_moderation/traces_nested.json --output-dir /tmp/moderation-demo
logicpearl inspect /tmp/moderation-demo
```
```

**Step 3: Improve the getting-started example**

The current `decision_traces.csv` has 12 rows and discovers `age >= 18` — trivially simple. The `synthetic_access_policy.tracegen.json` already defines a 5-feature, 3-rule, 240-row synthetic trace generator. Update the README quickstart to point at the synthetic trace flow as a more compelling first example, while keeping the CSV as the minimal "hello world."

Add to README after the initial quickstart block:
```markdown
For a more compelling example with multiple features and non-obvious rules:

```bash
logicpearl traces generate examples/getting_started/synthetic_access_policy.tracegen.json --output /tmp/synthetic_traces.csv
logicpearl build /tmp/synthetic_traces.csv --output-dir /tmp/synthetic-pearl
logicpearl inspect /tmp/synthetic-pearl
```

This discovers three rules from five features — results you couldn't eyeball from the CSV.
```

**Step 4: Commit**
```bash
git add examples/ README.md
git commit -m "docs: add demo READMEs, showcase multi-feature example in getting-started"
```

---

### Task 11: Add SPDX headers to source files

**Files:**
- All `*.rs` files in `crates/*/src/`

**Context:** No source files have SPDX license identifiers. Add `// SPDX-License-Identifier: MIT` as the first line of every `.rs` file in the workspace.

**Step 1: Add SPDX headers**

Use a script to prepend `// SPDX-License-Identifier: MIT` to all `.rs` source files:
```bash
find crates/ xtask/ -name '*.rs' -exec sed -i '' '1i\
// SPDX-License-Identifier: MIT
' {} \;
```

**Step 2: Verify build still passes**
```bash
cargo build --workspace
cargo test --workspace
```

**Step 3: Commit**
```bash
git add crates/ xtask/
git commit -m "chore: add SPDX-License-Identifier: MIT headers to all source files"
```

---

### Task 12: Document GateEvaluationResult field triplication

**Files:**
- Modify: `crates/logicpearl-runtime/src/lib.rs`

**Context:** `GateEvaluationResult` has `artifact_id`, `policy_id`, and `gate_id` all set to `gate.gate_id`. Same pattern for `ActionEvaluationResult`. Rather than collapsing (which would be a breaking API change at this stage), document why.

**Step 1: Add doc comments explaining the triplication**

```rust
/// Result of evaluating a gate artifact against an input.
///
/// Note: `artifact_id`, `policy_id`, and `gate_id` currently resolve to the same
/// value (`gate.gate_id`). They are separate fields to support future scenarios
/// where a single artifact contains multiple policies or where policy identity
/// differs from artifact identity (e.g., versioned artifact bundles).
pub struct GateEvaluationResult {
```

Do the same for `ActionEvaluationResult`:
```rust
/// Result of evaluating an action policy artifact.
///
/// Note: `artifact_id`, `policy_id`, and `action_policy_id` currently resolve
/// to the same value. See `GateEvaluationResult` for rationale.
pub struct ActionEvaluationResult {
```

**Step 2: Commit**
```bash
git add crates/logicpearl-runtime/
git commit -m "docs: document rationale for separate artifact/policy/gate ID fields"
```

---

### Task 13: Reserved crates publish=false and Python "yet" cleanup

**Files:**
- Modify: `reserved-crates/logicpearl-explain/Cargo.toml`
- Modify: `reserved-crates/logicpearl-policy/Cargo.toml`
- Modify: `reserved-crates/logicpearl-schema/Cargo.toml`
- Modify: `reserved-crates/logicpearl-wasm/Cargo.toml`
- Modify: `reserved-python/logicpearl/README.md`

**Step 1: Add publish = false to reserved crates** (if not already publishing)

Actually — these crates exist specifically TO be published as placeholders. The `reserved-crates/README.md` explains this clearly. Instead, add a note to the workspace README making the intent transparent. Skip changing `publish = false` — the README already explains the purpose honestly.

**Step 2: Fix "not a service client yet" in Python README**

Read `reserved-python/logicpearl/README.md` and remove or clarify the "yet" language. If there's no concrete plan for a hosted API, change to:
```
This is a local evaluation library, not a service client.
```

**Step 3: Commit**
```bash
git add reserved-python/
git commit -m "docs: clarify Python package is a local library, not a service client"
```
