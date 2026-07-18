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

from .dsl import PBinOp, PConst, PVVar
from .pattern import KnownPattern, PatternParam

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
    enabled_by_default=False,
)
