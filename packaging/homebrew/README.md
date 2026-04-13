# Homebrew Tap Packaging

LogicPearl publishes Homebrew support through a tap formula generated from the GitHub Release bundle checksums.

Release flow:

1. Push a version tag such as `v0.1.5`.
2. `.github/workflows/release-bundles.yml` builds the Linux and macOS bundles.
3. The publish job generates `logicpearl.rb` from the real `dist/*.tar.gz.sha256` files.
4. The formula is attached to the GitHub Release as `logicpearl.rb`.
5. If the `HOMEBREW_TAP_TOKEN` repository secret is configured, the workflow also commits the formula to `LogicPearlHQ/homebrew-tap` at `Formula/logicpearl.rb`.

To enable automatic tap updates, create `LogicPearlHQ/homebrew-tap` and add a `HOMEBREW_TAP_TOKEN` secret to the `LogicPearlHQ/logicpearl` repository. The token needs permission to push to the tap repository. Without that secret, the release still attaches `logicpearl.rb` as a GitHub Release asset for manual tap updates.

To generate the formula locally from release bundle checksums:

```bash
cargo xtask generate-homebrew-formula \
  --version 0.1.5 \
  --dist-dir dist \
  --output ../homebrew-tap/Formula/logicpearl.rb
```

Expected tap install command after the tap is published:

```bash
brew install LogicPearlHQ/tap/logicpearl
```

The formula installs the `logicpearl` binary from LogicPearl release bundles and uses Homebrew's `z3` dependency instead of linking the bundled solver into the global Homebrew prefix.
