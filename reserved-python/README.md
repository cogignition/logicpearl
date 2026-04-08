# Reserved Python Packages

These packages are intentionally minimal placeholders for realistic future `logicpearl*` names we may want on PyPI.

They are:
- outside the Rust workspace
- not part of the normal build or test flow
- meant only for clean namespace reservation when we are ready to publish them

Current reserved-name candidates:
- `logicpearl`

## Why This Exists

PyPI package names are first-come, first-served.

Publishing `logicpearl` on crates.io or npm does **not** protect the Python package name.

If we believe a name is plausibly part of the long-term public product surface, the cleanest way to protect it is to publish a small honest placeholder package before someone else claims it.

## Publish Intent

These placeholders should stay:
- small
- honest
- clearly documented

They should not pretend to be fully implemented libraries.

## Suggested Publish Flow

1. Check live availability.
2. Build the source distribution and wheel.
3. Upload with Twine.

Example:

```bash
python3 -m build reserved-python/logicpearl
python3 -m twine upload dist/logicpearl-*
```

## Naming Rule

Only add a placeholder here if the name is:
- realistic
- product-aligned
- likely to matter later

Do not fill this directory with speculative package names.
