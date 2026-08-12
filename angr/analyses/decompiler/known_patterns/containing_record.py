"""The CONTAINING_RECORD macro (Windows drivers) / container_of (Linux kernel):

    CONTAINING_RECORD(addr, type, field) == (type *)((char *)addr - offsetof(...))

which compiles to a bare pointer-minus-small-constant, ``(p Sub off)``. Too
generic to run unsolicited (any pointer arithmetic matches), so opt-in. The
matched offset is captured as an extra call argument, and the return type is a
pointer to a record struct reserving the leading ``off`` bytes (so Typehoon can
grow it from the record's field accesses).

Arch-independent shape (the offset is a captured constant, not word-scaled).

Three qualifications keep the *presentation* honest, all measured against putty
(user-space C, 139 real uses, DWARF ``offsetof`` as the oracle):

* **One call per idiom.** No compiler keeps the adjusted pointer around: it
  folds the subtraction into every field displacement that reads through it, so
  one source ``container_of`` reached the matcher as 3.4 separate matches on the
  same base, each naming a record base wrong by that field's offset (83.5% of
  the non-genuine matches were explained this way, against 13.0% for random
  offsets). ``collapse_capture`` keeps one match per base pointer; the largest
  offset is the right one to keep, since a field at member offset ``m`` of the
  record appears as ``p - (off - m)`` and so can only shrink the constant.
  Measured: this reports the true ``container_of`` offset for 80.1% (gcc) /
  86.7% (clang) of base pointers, against 29% for the per-field matches.

* **An offset floor.** ``p - 1`` is a decrement, not a record base; offsets
  below one machine word carry no record. 29 of the 85 distinct offsets emitted
  in container_of-free code were exactly 1.

**Rejected: requiring the result to be dereferenced.** The captured base is a
bare virtual variable of unknown type, so a decrement matches as happily as a
record base, and demanding that the adjusted pointer sit inside a memory address
looks like the way to tell them apart. It is exactly backwards. The *folded*
form is a field load and passes; the *unfolded* form -- the one that survives
because the code does something with the record other than read one field of it,
i.e. the case the pattern gets right -- does not, since the pointer is handed to
a callee or stored. Measured on putty/gcc it dropped function-level recall from
90.7% to 65.0% and site-level recall from 42.7% to 2.1%, and it also rejects the
``sum_list`` fixture below. The offset floor already removes the decrements it
was aimed at.
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


# smallest adjustment that can plausibly be a record base rather than a decrement
MIN_RECORD_OFFSET = 8


def _build_containing_record(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
    min_off = MIN_RECORD_OFFSET
    return KnownPattern(
        name="containing_record",
        display_name="CONTAINING_RECORD",
        call_name="CONTAINING_RECORD",
        pattern=PBinOp("Sub", (PVVar("p"), PConst(pred=lambda v: min_off <= v < 0x1000, name="off"))),
        params=(PatternParam("p"),),
        extra_args=("off",),
        returnty="void *",
        returnty_factory=_record_returnty,
        collapse_capture="p",
        collapse_max_capture="off",
    )


CONTAINING_RECORD_PATTERN = make_template("CONTAINING_RECORD", _build_containing_record, enabled_by_default=False)
