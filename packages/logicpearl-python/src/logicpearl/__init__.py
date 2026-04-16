"""Official Python bindings for ``logicpearl-engine``.

This package gives Python code a direct bridge to the Rust execution facade for:

- loading a pearl artifact bundle or `pearl.ir.json`
- loading a `pipeline.json`
- executing those artifacts on JSON-compatible Python input

It is intentionally not a CLI subprocess wrapper.
"""

from ._logicpearl import LogicPearlEngine, __version__, load_engine

__all__ = ["LogicPearlEngine", "load_engine", "__version__"]
