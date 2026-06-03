from __future__ import annotations

# The VEX -> AIL converter is implemented in Rust (`angr.rustylib.ailment`).
# This module re-exports it so existing imports keep working.
#
# ``VEXIRSBConverter`` exposes two staticmethods:
#   * ``convert(irsb, manager)``        -- convert a cached pyvex Python IRSB
#   * ``convert_from_lift(arch, addr, data, manager, **opts)`` -- the default
#     fast path: lift ``data`` directly into libVEX and convert the C IRSB
#     without materializing a pyvex Python IRSB.
from angr.rustylib.ailment import VEXIRSBConverter

__all__ = ["VEXIRSBConverter"]
