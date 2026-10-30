"""
A call to a variadic callee whose variadic arguments could not be determined may read any of its outgoing
stack-argument slots: from its first stack-argument slot (call-time sp, past the return address and the shadow space)
up to the caller's lowest frame-local slot above it. Dead-store elimination must keep the stores to those slots.
"""

from __future__ import annotations

from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Call, Load, Phi, StackBaseOffset, VirtualVariable
from angr.ailment.statement import Assignment

# set by CallSiteMaker on such a call: the first stack-argument slot relative to sp before the call
VARIADIC_UNRESOLVED_TAG = "variadic_unresolved"
# set as well when the stack pointer at the call is known: that slot as a StackBaseOffset offset
VARIADIC_STACK_ARGS_TAG = "variadic_stack_args_off"


def is_unresolved_variadic_call(call: Call) -> bool:
    return call.tags.get(VARIADIC_UNRESOLVED_TAG) is not None


class FrameUseCollector(AILBlockViewer):
    """
    Collects unresolved variadic calls and the frame offsets a function uses as locals: stack slots it reads or whose
    address it takes, except as a call's own stack argument or as a store's destination.
    """

    def __init__(self):
        super().__init__()
        self.calls: list[tuple[int, Call]] = []
        self.local_offsets: set[int] = set()

    def _handle_Assignment(self, stmt_idx, stmt, block):
        # the destination is a definition
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_WeakAssignment(self, stmt_idx, stmt, block):
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx, stmt, block):
        if not isinstance(stmt.addr, StackBaseOffset):
            self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if stmt.guard is not None:
            self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if is_unresolved_variadic_call(expr):
            self.calls.append((stmt_idx, expr))
        if not isinstance(expr.target, str):
            self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
        for i, arg in enumerate(expr.args or ()):
            if isinstance(arg, VirtualVariable) and arg.was_stack:
                continue
            if isinstance(arg, Load) and isinstance(arg.addr, StackBaseOffset):
                continue
            self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
        # merging versions of a slot is not a read
        return None

    def _handle_StackBaseOffset(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.offset, int):
            self.local_offsets.add(expr.offset)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.was_stack:
            self.local_offsets.add(expr.stack_offset)


def outgoing_area_end(start: int, local_offsets) -> int | None:
    """The caller's lowest frame-local slot at or above ``start``, or None if there is none."""
    return min((off for off in local_offsets if off >= start), default=None)


def variadic_call_read_vvars(blocks: dict, succs: dict) -> set[int]:
    """
    Stack variables whose value an unresolved variadic call may read: a backward liveness over frame bytes in which
    such a call reads its outgoing stack-argument area (every stack slot if the stack pointer at the call is unknown)
    and a stack-variable definition kills the bytes it writes.

    :param blocks:  Block key -> block.
    :param succs:   Block key -> successor block keys.
    :return:        Ids of the stack variables to keep.
    """
    collector = FrameUseCollector()
    calls: dict = {}
    defs: list = []
    for key, block in blocks.items():
        collector.calls = []
        collector.walk(block)
        if collector.calls:
            calls[key] = collector.calls
        defs.extend(
            stmt.dst
            for stmt in block.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack
        )
    if not calls or not defs:
        return set()

    lo = min(d.stack_offset for d in defs)
    hi = max(d.stack_offset + d.size for d in defs)

    def mask(start: int, end: int) -> int:
        start, end = max(start, lo), min(end, hi)
        return ((1 << (end - start)) - 1) << (start - lo) if start < end else 0

    reads: dict = {}
    for key, block_calls in calls.items():
        for stmt_idx, call in block_calls:
            start = call.tags.get(VARIADIC_STACK_ARGS_TAG)
            if start is None:
                reads[(key, stmt_idx)] = mask(lo, hi)
            else:
                end = outgoing_area_end(start, collector.local_offsets)
                reads[(key, stmt_idx)] = mask(start, hi if end is None else end)

    preds: dict = {key: [] for key in blocks}
    for key, ss in succs.items():
        for succ in ss:
            if succ in preds and key in blocks:
                preds[succ].append(key)

    kept: set[int] = set()

    def transfer(key, live: int, collect: bool) -> int:
        block = blocks[key]
        for stmt_idx in range(len(block.statements) - 1, -1, -1):
            stmt = block.statements[stmt_idx]
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
                written = mask(stmt.dst.stack_offset, stmt.dst.stack_offset + stmt.dst.size)
                if live & written:
                    if collect:
                        kept.add(stmt.dst.varid)
                    if not isinstance(stmt.src, Phi):
                        # a phi passes the earlier definitions through
                        live &= ~written
            read = reads.get((key, stmt_idx))
            if read:
                live |= read
        return live

    live_in = dict.fromkeys(blocks, 0)
    worklist = list(blocks)
    while worklist:
        key = worklist.pop()
        live_out = 0
        for succ in succs.get(key, ()):
            live_out |= live_in.get(succ, 0)
        new_in = transfer(key, live_out, False)
        if new_in != live_in[key]:
            live_in[key] = new_in
            worklist.extend(preds[key])

    for key in blocks:
        live_out = 0
        for succ in succs.get(key, ()):
            live_out |= live_in.get(succ, 0)
        transfer(key, live_out, True)
    return kept
