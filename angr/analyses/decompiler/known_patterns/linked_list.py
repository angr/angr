"""Doubly-linked-list idioms shared by Windows ``LIST_ENTRY`` (Flink/Blink) and
Linux kernel ``list_head`` (next/prev) — the same two-pointer layout, so one
set of templates matches both WDK drivers and kernel/Boost-intrusive code.

Covers the empty test, head init, unlink (``RemoveEntryList`` / ``__list_del_entry``),
head/tail insertion (``InsertHeadList`` / ``list_add``, ``InsertTailList`` /
``list_add_tail``), the two unlink supersets the kernel actually calls —
``list_del`` (unlink + LIST_POISON1/2 stores) and ``list_del_init`` (unlink +
re-init) — and the ``hlist_del`` diamond. The supersets rely on the finder
preferring the largest match, so they win over the bare unlink they contain.

The link offsets are word-scaled from the :class:`PatternContext`, so the same
definitions work on 32- and 64-bit. Opt-in (genericish C idioms). Calibrated
against tests/x86_64/windows/known_patterns_wdk_list.exe and
tests/x86_64/decompiler/known_patterns_linux_list (both -O2, SLP off); the
compiler orders the link loads/stores freely, so the multi-statement idioms use
unordered statement-set matching (``hlist_del`` excepted: PGraphPat block bodies
only support ordered matching).

``hlist_add_head`` is deliberately absent — its last two stores land in the
diamond's join block, and ``_outline_graph`` requires every interior block to be
fully consumed, so the idiom cannot be outlined without misrepresenting it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .dsl import PAssign, PBinOp, PBlockPat, PCondJump, PConst, PGraphPat, PLoad, PStmtSeq, PStore, PVVar
from .layouts import list_next_offset, list_prev_offset
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext


# <linux/poison.h>: LIST_POISON1/2 are POISON_POINTER_DELTA + 0x100 / + 0x122.
# POISON_POINTER_DELTA is CONFIG_ILLEGAL_POINTER_VALUE -- 0xdead000000000000 on
# x86-64 and arm64. Requiring a non-zero high half keeps the fingerprint strong
# (with a zero delta the poisons degrade to the very common 0x100 / 0x122) and
# incidentally restricts the pattern to 64-bit targets, where it belongs.
_POISON1_LOW = 0x100
_POISON2_LOW = 0x122


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


def _unlink_stmts(ctx: PatternContext) -> tuple:
    """__list_del_entry(entry) / the RemoveEntryList core: prev = entry->Blink;
    next = entry->Flink; prev->Flink = next; next->Blink = prev."""
    ws = ctx.word_size
    return (
        PAssign(PVVar("prev"), _field("entry", list_prev_offset(ctx), ws)),
        PAssign(PVVar("next"), _field("entry", list_next_offset(ctx), ws)),
        PStore(_addr("prev", list_next_offset(ctx)), PVVar("next"), size=ws),
        PStore(_addr("next", list_prev_offset(ctx)), PVVar("prev"), size=ws),
    )


def _build_remove_entry_list(ctx: PatternContext) -> KnownPattern:
    # prev = e->Blink; next = e->Flink; prev->Flink = next; next->Blink = prev  (any order)
    return KnownPattern(
        name="remove_entry_list",
        display_name="RemoveEntryList",
        call_name="RemoveEntryList",
        pattern=PStmtSeq(_unlink_stmts(ctx), ordered=False),
        params=(PatternParam("entry"),),
        returnty=None,
    )


def _build_insert_head_list(ctx: PatternContext) -> KnownPattern:
    # list_add(new, head) / InsertHeadList(head, entry):
    #   next = head->Flink; next->Blink = new; new->Flink = next;
    #   new->Blink = head; head->Flink = new  (any order)
    ws = ctx.word_size
    nx, pv = list_next_offset(ctx), list_prev_offset(ctx)
    return KnownPattern(
        name="insert_head_list",
        display_name="InsertHeadList",
        call_name="InsertHeadList",
        pattern=PStmtSeq(
            (
                PAssign(PVVar("next"), _field("list", nx, ws)),
                PStore(_addr("next", pv), PVVar("entry"), size=ws),
                PStore(_addr("entry", nx), PVVar("next"), size=ws),
                PStore(_addr("entry", pv), PVVar("list"), size=ws),
                PStore(_addr("list", nx), PVVar("entry"), size=ws),
            ),
            ordered=False,
        ),
        params=(PatternParam("list"), PatternParam("entry")),
        returnty=None,
    )


def _build_insert_tail_list(ctx: PatternContext) -> KnownPattern:
    # list_add_tail(new, head) / InsertTailList(head, entry):
    #   prev = head->Blink; head->Blink = new; new->Flink = head;
    #   new->Blink = prev; prev->Flink = new  (any order)
    ws = ctx.word_size
    nx, pv = list_next_offset(ctx), list_prev_offset(ctx)
    return KnownPattern(
        name="insert_tail_list",
        display_name="InsertTailList",
        call_name="InsertTailList",
        pattern=PStmtSeq(
            (
                PAssign(PVVar("prev"), _field("list", pv, ws)),
                PStore(_addr("list", pv), PVVar("entry"), size=ws),
                PStore(_addr("entry", nx), PVVar("list"), size=ws),
                PStore(_addr("entry", pv), PVVar("prev"), size=ws),
                PStore(_addr("prev", nx), PVVar("entry"), size=ws),
            ),
            ordered=False,
        ),
        params=(PatternParam("list"), PatternParam("entry")),
        returnty=None,
    )


def _poison(low: int) -> PConst:
    return PConst(pred=lambda v: (v & 0xFFFF) == low and (v >> 48) != 0, name=f"poison_{low:#x}")


def _poisons_agree(bindings) -> bool:
    p1 = bindings.get(f"poison_{_POISON1_LOW:#x}")
    p2 = bindings.get(f"poison_{_POISON2_LOW:#x}")
    return p1 is not None and p2 is not None and p2.value - p1.value == _POISON2_LOW - _POISON1_LOW


def _build_list_del(ctx: PatternContext) -> KnownPattern:
    # the real kernel list_del(): unlink, then poison both links. The two
    # LIST_POISON constants make this a near-exact fingerprint, so it is kept
    # distinct from the plain RemoveEntryList unlink it contains.
    ws = ctx.word_size
    nx, pv = list_next_offset(ctx), list_prev_offset(ctx)
    return KnownPattern(
        name="list_del",
        display_name="list_del",
        call_name="list_del",
        pattern=PStmtSeq(
            (
                *_unlink_stmts(ctx),
                PStore(_addr("entry", nx), _poison(_POISON1_LOW), size=ws),
                PStore(_addr("entry", pv), _poison(_POISON2_LOW), size=ws),
            ),
            ordered=False,
        ),
        params=(PatternParam("entry"),),
        returnty=None,
        where=_poisons_agree,
    )


def _build_list_del_init(ctx: PatternContext) -> KnownPattern:
    # list_del_init(entry): __list_del_entry(entry); INIT_LIST_HEAD(entry)
    ws = ctx.word_size
    nx, pv = list_next_offset(ctx), list_prev_offset(ctx)
    return KnownPattern(
        name="list_del_init",
        display_name="list_del_init",
        call_name="list_del_init",
        pattern=PStmtSeq(
            (
                *_unlink_stmts(ctx),
                PStore(_addr("entry", nx), PVVar("entry"), size=ws),
                PStore(_addr("entry", pv), PVVar("entry"), size=ws),
            ),
            ordered=False,
        ),
        params=(PatternParam("entry"),),
        returnty=None,
    )


def _build_hlist_del(ctx: PatternContext) -> KnownPattern:
    # __hlist_del(n): next = n->next; pprev = n->pprev; *pprev = next;
    #                 if (next) next->pprev = pprev;
    # a control-flow diamond, so a two-block graph pattern whose join is the
    # region's single exit. hlist_node {next, pprev} has the same two-pointer
    # layout as list_head, so the same offsets apply. Also matches the poisoned
    # hlist_del(), whose two poison stores land in the join block and stay put.
    ws = ctx.word_size
    nx, pv = list_next_offset(ctx), list_prev_offset(ctx)
    return KnownPattern(
        name="hlist_del",
        display_name="hlist_del",
        call_name="hlist_del",
        pattern=PGraphPat(
            blocks={
                "entry": PBlockPat(
                    "entry",
                    PStmtSeq(
                        (
                            PAssign(PVVar("next"), _field("node", nx, ws)),
                            PAssign(PVVar("pprev"), _field("node", pv, ws)),
                            PStore(PVVar("pprev"), PVVar("next"), size=ws),
                            PCondJump(PBinOp("CmpEQ", (PVVar("next"), PConst(0)))),
                        ),
                        allow_gaps=False,
                    ),
                ),
                "relink": PBlockPat(
                    "relink",
                    PStmtSeq((PStore(_addr("next", pv), PVVar("pprev"), size=ws),), allow_gaps=False),
                ),
            },
            edges=[("entry", "relink"), ("entry", "join"), ("relink", "join")],
            entry="entry",
        ),
        params=(PatternParam("node"),),
        returnty=None,
    )


IS_LIST_EMPTY = make_template("IsListEmpty", _build_is_list_empty, enabled_by_default=False)
INITIALIZE_LIST_HEAD = make_template("InitializeListHead", _build_initialize_list_head, enabled_by_default=False)
REMOVE_ENTRY_LIST = make_template("RemoveEntryList", _build_remove_entry_list, enabled_by_default=False)
INSERT_HEAD_LIST = make_template("InsertHeadList", _build_insert_head_list, enabled_by_default=False)
INSERT_TAIL_LIST = make_template("InsertTailList", _build_insert_tail_list, enabled_by_default=False)
LIST_DEL = make_template("list_del", _build_list_del, enabled_by_default=False)
LIST_DEL_INIT = make_template("list_del_init", _build_list_del_init, enabled_by_default=False)
HLIST_DEL = make_template("hlist_del", _build_hlist_del, enabled_by_default=False)

ALL_LINKED_LIST_TEMPLATES = [
    IS_LIST_EMPTY,
    INITIALIZE_LIST_HEAD,
    REMOVE_ENTRY_LIST,
    INSERT_HEAD_LIST,
    INSERT_TAIL_LIST,
    LIST_DEL,
    LIST_DEL_INIT,
    HLIST_DEL,
]
