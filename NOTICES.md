# Third-Party Notices

LogicPearl includes dependencies under the following licenses. All are permissive.

## License Elections

- **r-efi**: Licensed under MIT OR Apache-2.0 OR LGPL-2.1-or-later. This project elects **MIT**.

## Notable Dependencies

- **unsafe-libyaml** (via `serde_yaml`): MIT-licensed pure-Rust port of libyaml by dtolnay. Despite the name, this is not an FFI binding to system libyaml.
- **ed25519-dalek** and curve dependencies: BSD-3-Clause. Used for decision receipt signing in `logicpearl-conformance`.

Run `cargo deny check licenses` to audit the full dependency tree.
