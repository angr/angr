"""Doubly-linked-list idioms shared by Windows ``LIST_ENTRY`` (Flink/Blink) and
Linux kernel ``list_head`` (next/prev) — the same two-pointer layout, so one
set of templates matches both WDK drivers and kernel/Boost-intrusive code.

The link offsets are word-scaled from the :class:`PatternContext`, so the same
definitions work on 32- and 64-bit. Opt-in (genericish C idioms). Calibrated
against tests/x86_64/windows/known_patterns_wdk_list.exe and
tests/x86_64/decompiler/known_patterns_linux_list (both -O2, SLP off); the
compiler orders the link loads/stores freely, so the multi-statement idioms use
unordered statement-set matching.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .dsl import PAssign, PBinOp, PConst, PLoad, PStmtSeq, PStore, PVVar
from .layouts import list_next_offset, list_prev_offset
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext


def _field(cap: str, off: int, size: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=size)


def _addr(cap: str, off: int):
    return PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))


def _build_is_list_empty(ctx: PatternContext) -> KnownPattern:
    # head->Flink == head  ==  Load(h + next) CmpEQ h
    return KnownPattern(
        name="is_list_empty",
        display_name="IsListEmpty",
        call_name="IsListEmpty",
        pattern=PBinOp("CmpEQ", (_field("list", list_next_offset(ctx), ctx.word_size), PVVar("list"))),
        params=(PatternParam("list"),),
        returnty="int",
    )


def _build_initialize_list_head(ctx: PatternContext) -> KnownPattern:
    # h->Flink = h->Blink = h  ==  Store(h+next, h); Store(h+prev, h)  (any order)
    ws = ctx.word_size
    return KnownPattern(
        name="initialize_list_head",
        display_name="InitializeListHead",
        call_name="InitializeListHead",
        pattern=PStmtSeq(
            (
                PStore(_addr("list", list_next_offset(ctx)), PVVar("list"), size=ws),
                PStore(_addr("list", list_prev_offset(ctx)), PVVar("list"), size=ws),
            ),
            ordered=False,
        ),
        params=(PatternParam("list"),),
        returnty=None,
    )


def _build_remove_entry_list(ctx: PatternContext) -> KnownPattern:
    # prev = e->Blink; next = e->Flink; prev->Flink = next; next->Blink = prev  (any order)
    ws = ctx.word_size
    return KnownPattern(
        name="remove_entry_list",
        display_name="RemoveEntryList",
        call_name="RemoveEntryList",
        pattern=PStmtSeq(
            (
                PAssign(PVVar("prev"), _field("entry", list_prev_offset(ctx), ws)),
                PAssign(PVVar("next"), _field("entry", list_next_offset(ctx), ws)),
                PStore(_addr("prev", list_next_offset(ctx)), PVVar("next"), size=ws),
                PStore(_addr("next", list_prev_offset(ctx)), PVVar("prev"), size=ws),
            ),
            ordered=False,
        ),
        params=(PatternParam("entry"),),
        returnty=None,
    )


IS_LIST_EMPTY = make_template("IsListEmpty", _build_is_list_empty, enabled_by_default=False)
INITIALIZE_LIST_HEAD = make_template("InitializeListHead", _build_initialize_list_head, enabled_by_default=False)
REMOVE_ENTRY_LIST = make_template("RemoveEntryList", _build_remove_entry_list, enabled_by_default=False)

ALL_LINKED_LIST_TEMPLATES = [IS_LIST_EMPTY, INITIALIZE_LIST_HEAD, REMOVE_ENTRY_LIST]
