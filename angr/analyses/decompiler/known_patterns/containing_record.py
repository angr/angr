"""The CONTAINING_RECORD macro (Windows drivers) / container_of (Linux kernel):

    CONTAINING_RECORD(addr, type, field) == (type *)((char *)addr - offsetof(...))

which compiles to a bare pointer-minus-small-constant, ``(p Sub off)``. Too
generic to run unsolicited (any pointer arithmetic matches), so opt-in. The
matched offset is captured as an extra call argument, and the return type is a
pointer to a record struct reserving the leading ``off`` bytes (so Typehoon can
grow it from the record's field accesses).

Arch-independent shape (the offset is a captured constant, not word-scaled).
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from angr.sim_type import SimStruct, SimType, SimTypeArray, SimTypeChar, SimTypePointer

from .dsl import PBinOp, PConst, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    import archinfo

    from .context import PatternContext


def _record_returnty(arch: archinfo.Arch, const_args: dict[str, int]) -> SimType | None:
    off = const_args.get("off")
    if not isinstance(off, int) or off <= 0:
        return None
    record = SimStruct(OrderedDict([("gap0", SimTypeArray(SimTypeChar(), length=off))]), name=f"record_{off:x}")
    return SimTypePointer(record).with_arch(arch)


def _build_containing_record(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="containing_record",
        display_name="CONTAINING_RECORD",
        call_name="CONTAINING_RECORD",
        pattern=PBinOp("Sub", (PVVar("p"), PConst(pred=lambda v: 0 < v < 0x1000, name="off"))),
        params=(PatternParam("p"),),
        extra_args=("off",),
        returnty="void *",
        returnty_factory=_record_returnty,
    )


CONTAINING_RECORD_PATTERN = make_template("CONTAINING_RECORD", _build_containing_record, enabled_by_default=False)
