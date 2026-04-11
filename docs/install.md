# Install LogicPearl

The easiest way to get started is the prebuilt installer. It installs:

- `logicpearl`
- a bundled `z3`
- verifies the downloaded release archive against its published SHA-256 checksum

That is the normal public CLI path. You do not need to install Z3 separately first.

## Fastest Install

```bash
curl -fsSL https://raw.githubusercontent.com/LogicPearlHQ/logicpearl/main/install.sh | sh
logicpearl quickstart
```

By default the installer:

- stores versioned bundles under `~/.logicpearl/releases`
- points `~/.logicpearl/current` at the active version
- creates `logicpearl` and `z3` symlinks in `~/.local/bin`

If `~/.local/bin` is not already on your `PATH`, add it and open a new shell.

## Supported Prebuilt Targets

The installer currently resolves these release bundles:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Prebuilt Windows and Linux arm64 bundles are not published yet. If your machine is outside the set above, use the source-install path below.

## Install A Specific Version

```bash
curl -fsSL https://raw.githubusercontent.com/LogicPearlHQ/logicpearl/main/install.sh | sh -s -- --version 0.1.4
```

## Custom Install Locations

```bash
curl -fsSL https://raw.githubusercontent.com/LogicPearlHQ/logicpearl/main/install.sh | sh -s -- \
  --install-root "$HOME/.logicpearl" \
  --bin-dir "$HOME/.local/bin"
```

## Manual Bundle Install

If you prefer not to pipe the installer into `sh`, download the release bundle directly from GitHub Releases and extract it yourself.

Each release bundle also ships with a `.sha256` sidecar file. Verify the archive before extraction if you install it manually.

Each bundle contains:

- `bin/logicpearl`
- `bin/z3`
- `bundle_manifest.json`
- bundle notes and notices

After extraction, put the contents of `bin/` on your `PATH`.

## Source Install

If you want to build from source instead of using the prebuilt bundle:

```bash
cargo install --path crates/logicpearl
```

That path builds the CLI only. For normal build/discovery workflows you still need a solver available. The simplest source-build setup is to install `z3` separately and make sure it is on your `PATH`.

## Optional cvc5

`cvc5` is an optional secondary backend for solver bring-up and parity testing. It is not required for the default LogicPearl install path.

If you are working on solver backend development, see [CONTRIBUTING.md](../CONTRIBUTING.md).
