"""Shim re-exporting the Rust Block implementation.

The actual class lives in ``angr.rustylib.ailment`` (Rust + PyO3); this module
exists so existing imports ``from angr.ailment.block import Block`` keep
working.
"""

from __future__ import annotations

from angr.rustylib.ailment import Block  # pylint:disable=import-error

__all__ = ["Block"]
