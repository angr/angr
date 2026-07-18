"""The CONTAINING_RECORD macro, ubiquitous in Windows driver code:

    CONTAINING_RECORD(addr, type, field)
        == (type *)((char *)(addr) - offsetof(type, field))

which compiles to a bare pointer-minus-small-constant:

    (p Sub off<64>)

This shape is far too generic to run unsolicited (any pointer arithmetic
matches), so the pattern is not enabled by default; pass it explicitly via
``KnownPatternFinder(patterns=[CONTAINING_RECORD_PATTERN])``.

Calibrated against tests/x86_64/windows/known_patterns_containing_record.exe
(x86_64-w64-mingw32-gcc -O2): the record pointer appears as
``Call(consume, ((vvar Sub 8<64>)))``.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from angr.sim_type import SimStruct, SimType, SimTypeArray, SimTypeChar, SimTypePointer

from .dsl import PBinOp, PConst, PVVar
from .pattern import KnownPattern, PatternParam

if TYPE_CHECKING:
    import archinfo


def _record_returnty(arch: archinfo.Arch, const_args: dict[str, int]) -> SimType | None:
    """CONTAINING_RECORD(p, T, field) returns a pointer to a record T whose
    ``field`` member sits at the matched offset. T itself is unknown at pattern
    time, so hint a struct that reserves the leading ``off`` bytes; Typehoon
    merges it with the record's observed field accesses (the constraint is a
    Subtype, not an Equivalence, precisely so the struct can grow)."""
    off = const_args.get("off")
    if not isinstance(off, int) or off <= 0:
        return None
    record = SimStruct(
        OrderedDict([("gap0", SimTypeArray(SimTypeChar(), length=off))]),
        name=f"record_{off:x}",
    )
    return SimTypePointer(record).with_arch(arch)


CONTAINING_RECORD_PATTERN = KnownPattern(
    name="containing_record",
    display_name="CONTAINING_RECORD",
    call_name="CONTAINING_RECORD",
    pattern=PBinOp(
        "Sub",
        (
            PVVar("p"),
            PConst(pred=lambda v: 0 < v < 0x1000, name="off"),
        ),
    ),
    params=(PatternParam("p"),),
    extra_args=("off",),
    returnty="void *",
    returnty_factory=_record_returnty,
    enabled_by_default=False,
)
