# Install LogicPearl

After any install path, run:

```bash
logicpearl quickstart
```

That command prints the shortest command recipes. Use `logicpearl quickstart build` after cloning the repository when you want to run the checked-in example traces.

The recommended public CLI path is a prebuilt release bundle that you download, verify against its published SHA-256 checksum, then extract locally. The bundle includes:

- `logicpearl`
- a bundled `z3`
- `bundle_manifest.json`
- license and notice files

You do not need to install Z3 separately for the prebuilt path.

## Verified Bundle Install

Choose the target that matches your machine:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Then download the release archive and checksum sidecar:

```bash
TARGET="aarch64-apple-darwin"
BASE="https://github.com/LogicPearlHQ/logicpearl/releases/latest/download"
ARCHIVE="logicpearl-${TARGET}.tar.gz"
INSTALL_DIR="$(mktemp -d)"

curl -fsSL "$BASE/$ARCHIVE" -o "$INSTALL_DIR/$ARCHIVE"
curl -fsSL "$BASE/$ARCHIVE.sha256" -o "$INSTALL_DIR/$ARCHIVE.sha256"
EXPECTED="$(awk 'NF { print $1; exit }' "$INSTALL_DIR/$ARCHIVE.sha256")"
ACTUAL="$(if command -v sha256sum >/dev/null 2>&1; then sha256sum "$INSTALL_DIR/$ARCHIVE"; else shasum -a 256 "$INSTALL_DIR/$ARCHIVE"; fi | awk '{ print $1 }')"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "checksum mismatch for $ARCHIVE" >&2
  exit 1
fi

tar -xzf "$INSTALL_DIR/$ARCHIVE" -C "$INSTALL_DIR"
BUNDLE_DIR="$(find "$INSTALL_DIR" -maxdepth 1 -type d -name "logicpearl-v*-${TARGET}" | head -n 1)"
if [ -z "$BUNDLE_DIR" ]; then
  echo "downloaded archive did not contain a LogicPearl bundle directory" >&2
  exit 1
fi
export PATH="$BUNDLE_DIR/bin:$PATH"

logicpearl quickstart
```

That `export PATH=...` line is session-local. For a persistent install:

```bash
mkdir -p "$HOME/.logicpearl/releases" "$HOME/.local/bin"
cp -R "$BUNDLE_DIR" "$HOME/.logicpearl/releases/"
ln -sfn "$HOME/.logicpearl/releases/$(basename "$BUNDLE_DIR")" "$HOME/.logicpearl/current"
ln -sfn "$HOME/.logicpearl/current/bin/logicpearl" "$HOME/.local/bin/logicpearl"
ln -sfn "$HOME/.logicpearl/current/bin/z3" "$HOME/.local/bin/z3"
```

If `~/.local/bin` is not already on your `PATH`, add it:

```bash
# zsh (macOS default):
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

# bash:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

## Homebrew

Homebrew users can install from the release tap formula when it is available:

```bash
brew install LogicPearlHQ/tap/logicpearl
logicpearl quickstart
```

The tap formula is generated from the same GitHub Release bundle checksums used by the verified bundle path above. See [packaging/homebrew](../packaging/homebrew/) for the release automation.

## Install A Specific Version

Use a versioned release URL instead of `latest`:

```bash
VERSION="0.1.5"
TARGET="aarch64-apple-darwin"
BASE="https://github.com/LogicPearlHQ/logicpearl/releases/download/v${VERSION}"
ARCHIVE="logicpearl-${TARGET}.tar.gz"
```

Then run the same download, checksum, extraction, and PATH steps from the verified bundle flow.

## Convenience Installer

The installer performs the same archive download and checksum verification, then installs versioned bundles under `~/.logicpearl/releases` and symlinks `logicpearl` and `z3` into `~/.local/bin`.

This path executes a shell script fetched from `raw.githubusercontent.com`. Read the script first or use the verified bundle flow above if you do not want to run remote shell code.

```bash
curl -fsSL https://raw.githubusercontent.com/LogicPearlHQ/logicpearl/main/install.sh | sh
logicpearl quickstart
```

Install a specific version with the convenience installer:

```bash
curl -fsSL https://raw.githubusercontent.com/LogicPearlHQ/logicpearl/main/install.sh | sh -s -- --version 0.1.5
```

Use custom install locations:

```bash
curl -fsSL https://raw.githubusercontent.com/LogicPearlHQ/logicpearl/main/install.sh | sh -s -- \
  --install-root "$HOME/.logicpearl" \
  --bin-dir "$HOME/.local/bin"
```

## Supported Prebuilt Targets

Prebuilt release bundles are currently published for:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Prebuilt Windows and Linux arm64 bundles are not published yet. If your machine is outside the set above, use the source-install path below.

## Source Install

If you want to build from a cloned source checkout instead of using the prebuilt bundle, run this from the repository root:

```bash
cargo install --path crates/logicpearl
```

That path builds the CLI only. Use the workspace-local crate path because the checked-in examples and CLI crate live in this repository. For normal build/discovery workflows you still need a solver available. The simplest source-build setup is to install `z3` separately and make sure it is on your `PATH`.

## Optional cvc5

`cvc5` is an optional secondary backend for solver bring-up and parity testing. It is not required for the default LogicPearl install path.

If you are working on solver backend development, see [CONTRIBUTING.md](../CONTRIBUTING.md).
