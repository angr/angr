"""Shim for ``from angr.ailment.block import Block``."""

from __future__ import annotations

from angr.rustylib.ailment import Block  # pylint:disable=import-error

__all__ = ["Block"]
