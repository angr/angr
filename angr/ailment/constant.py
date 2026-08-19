from __future__ import annotations

#: Marker size for Load expressions whose size is not known yet. It must be positive and small enough that
#: ``UNDETERMINED_SIZE * 8`` fits in a u32: Load stores its bit width in an unsigned 32-bit header, so a negative or
#: overly large sentinel would wrap around and no longer compare equal to itself.
UNDETERMINED_SIZE = 0x1FFFC0DE
