from __future__ import annotations

# The Manager class is implemented in Rust (`angr.rustylib.ailment`). This
# module re-exports it so existing imports (`from angr.ailment.manager import
# Manager`) keep working.
from angr.rustylib.ailment import Manager

__all__ = ["Manager"]
