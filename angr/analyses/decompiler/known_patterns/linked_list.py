"""Doubly-linked-list idioms shared by Windows ``LIST_ENTRY`` (Flink/Blink) and
Linux kernel ``list_head`` (next/prev) — the same two-pointer layout, so one
set of patterns matches both WDK drivers and kernel/Boost-intrusive code.

Calibrated against tests/x86_64/windows/known_patterns_wdk_list.exe
(x86_64-w64-mingw32-gcc -O2 -fno-tree-slp-vectorize) and
tests/x86_64/decompiler/known_patterns_linux_list (gcc -O2, likewise). The two
sources emit the same statement shapes but the compiler chooses the order of
the link loads/stores freely, so the multi-statement idioms use unordered
statement-set matching (``PStmtSeq(..., ordered=False)``).
"""

from __future__ import annotations

from .dsl import PAssign, PBinOp, PConst, PLoad, PStmtSeq, PStore, PVVar
from .pattern import KnownPattern, PatternParam


def _add8(cap: str) -> PBinOp:
    return PBinOp("Add", (PVVar(cap), PConst(8)))


# IsListEmpty(h) / list_empty(h): head->Flink == head  ==  Load(h) CmpEQ h
# (the decompiler wraps this in Extract(Conv(1->64, ...)); the finder matches
# the inner comparison as a sub-expression).
IS_LIST_EMPTY = KnownPattern(
    name="is_list_empty",
    display_name="IsListEmpty",
    call_name="IsListEmpty",
    pattern=PBinOp("CmpEQ", (PLoad(PVVar("list")), PVVar("list"))),
    params=(PatternParam("list"),),
    returnty="int",
    enabled_by_default=False,
)


# InitializeListHead(h) / INIT_LIST_HEAD(h): h->Flink = h->Blink = h
#   Store(h, h); Store(h + 8, h)   (either order)
INITIALIZE_LIST_HEAD = KnownPattern(
    name="initialize_list_head",
    display_name="InitializeListHead",
    call_name="InitializeListHead",
    pattern=PStmtSeq(
        (
            PStore(PVVar("list"), PVVar("list"), size=8),
            PStore(_add8("list"), PVVar("list"), size=8),
        ),
        ordered=False,
    ),
    params=(PatternParam("list"),),
    returnty=None,
    enabled_by_default=False,
)


# RemoveEntryList(e) / list_del(e):
#   prev = e->Blink;  next = e->Flink;  prev->Flink = next;  next->Blink = prev;
#   =  p = Load(e+8); n = Load(e); Store(p, n); Store(n+8, p)   (any order)
REMOVE_ENTRY_LIST = KnownPattern(
    name="remove_entry_list",
    display_name="RemoveEntryList",
    call_name="RemoveEntryList",
    pattern=PStmtSeq(
        (
            PAssign(PVVar("prev"), PLoad(_add8("entry"), size=8)),
            PAssign(PVVar("next"), PLoad(PVVar("entry"), size=8)),
            PStore(PVVar("prev"), PVVar("next"), size=8),  # prev->Flink = next
            PStore(_add8("next"), PVVar("prev"), size=8),  # next->Blink = prev
        ),
        ordered=False,
    ),
    params=(PatternParam("entry"),),
    returnty=None,
    enabled_by_default=False,
)

ALL_LINKED_LIST_PATTERNS = [
    IS_LIST_EMPTY,
    INITIALIZE_LIST_HEAD,
    REMOVE_ENTRY_LIST,
]
