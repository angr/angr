"""
A call to a variadic callee whose variadic arguments could not be determined may read any of its outgoing
stack-argument slots: from its first variadic stack-argument slot (past the fixed arguments, the return address and the
shadow space) up to the caller's lowest frame-local slot above it. A frame-local slot is one whose address is taken or
whose value the caller still reads after the call; an outgoing argument is dead once the call returns. Dead-store
elimination must keep the stores to the slots in between.
"""

from __future__ import annotations

from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Call, Load, Phi, StackBaseOffset, VirtualVariable
from angr.ailment.statement import Assignment, SideEffectStatement

# set by CallSiteMaker on such a call: the first variadic stack-argument slot relative to sp before the call
VARIADIC_UNRESOLVED_TAG = "variadic_unresolved"
# set as well when the stack pointer at the call is known: that slot as a StackBaseOffset offset
VARIADIC_STACK_ARGS_TAG = "variadic_stack_args_off"


def is_unresolved_variadic_call(call: Call) -> bool:
    return call.tags.get(VARIADIC_UNRESOLVED_TAG) is not None


def block_variadic_tags(block) -> tuple:
    """The variadic tags of the call ending a block (CallSiteMaker's position), or () if it ends with none."""
    stmt = block.statements[-1] if block.statements else None
    expr = stmt.expr if isinstance(stmt, SideEffectStatement) else getattr(stmt, "src", None)
    if not isinstance(expr, Call):
        # Convert, Insert or Extract around the call
        expr = next((e for a in ("operand", "value", "base") if isinstance(e := getattr(expr, a, None), Call)), None)
    if expr is None:
        return ()
    return expr.tags.get(VARIADIC_UNRESOLVED_TAG), expr.tags.get(VARIADIC_STACK_ARGS_TAG)


class FrameUseCollector(AILBlockViewer):
    """
    Collects unresolved variadic calls, the frame offsets whose address is taken (other than as a store's destination
    or a call's own stack argument), and the stack variables each statement reads.
    """

    def __init__(self):
        super().__init__()
        self.calls: list[tuple[int, Call]] = []
        self.address_taken: set[int] = set()
        self.reads: dict[int, list[tuple[int, int]]] = {}

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
            if isinstance(arg, Load) and isinstance(arg.addr, StackBaseOffset):
                continue
            self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
        # merging versions of a slot is not a read
        return None

    def _handle_StackBaseOffset(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.offset, int):
            self.address_taken.add(expr.offset)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.was_stack:
            self.reads.setdefault(stmt_idx, []).append((expr.stack_offset, expr.size))


def outgoing_area_end(start: int, local_offsets) -> int | None:
    """The caller's lowest frame-local slot at or above ``start``, or None if there is none."""
    return min((off for off in local_offsets if off >= start), default=None)


def _stack_def(stmt):
    if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
        return stmt.dst
    return None


def variadic_call_read_vvars(blocks: dict, succs: dict) -> set[int]:
    """
    Stack variables whose value an unresolved variadic call may read. Two backward liveness passes over frame bytes:
    one over the function's own reads finds the slots live after each such call (frame locals, which bound its
    outgoing-argument area); the second has each such call read its area (every slot if the stack pointer at the call
    is unknown) and collects the definitions that reach a read.

    :param blocks:  Block key -> block.
    :param succs:   Block key -> successor block keys.
    :return:        Ids of the stack variables to keep.
    """
    calls: dict = {}
    reads_at: dict = {}
    address_taken: set[int] = set()
    defs = []
    for key, block in blocks.items():
        collector = FrameUseCollector()
        collector.walk(block)
        if collector.calls:
            calls[key] = collector.calls
        reads_at[key] = collector.reads
        address_taken |= collector.address_taken
        defs.extend(d for d in map(_stack_def, block.statements) if d is not None)
    if not calls or not defs:
        return set()

    # frame bytes are tracked in segments between the boundaries of every interval involved
    points = {p for d in defs for p in (d.stack_offset, d.stack_offset + d.size)}
    for reads in reads_at.values():
        for slots in reads.values():
            points.update(p for off, size in slots for p in (off, off + size))
    starts = {
        call.tags.get(VARIADIC_STACK_ARGS_TAG) for block_calls in calls.values() for _, call in block_calls
    } - {None}
    points |= starts | address_taken
    points = sorted(points)
    index = {p: i for i, p in enumerate(points)}
    lo, hi = points[0], points[-1]

    def mask(start: int, end: int) -> int:
        start, end = max(start, lo), min(end, hi)
        if start >= end:
            return 0
        return ((1 << (index[end] - index[start])) - 1) << index[start]

    preds: dict = {key: [] for key in blocks}
    for key, ss in succs.items():
        for succ in ss:
            if succ in preds and key in blocks:
                preds[succ].append(key)

    def solve(gen_of, on_def=None, on_stmt=None) -> None:
        """Backward fixpoint; gen_of(key, stmt_idx) gives the bytes a statement reads."""

        def transfer(key, live: int, final: bool) -> int:
            block = blocks[key]
            for stmt_idx in range(len(block.statements) - 1, -1, -1):
                if final and on_stmt is not None:
                    on_stmt(key, stmt_idx, live)
                stmt = block.statements[stmt_idx]
                dst = _stack_def(stmt)
                if dst is not None:
                    written = mask(dst.stack_offset, dst.stack_offset + dst.size)
                    if final and on_def is not None and live & written:
                        on_def(dst)
                    if not isinstance(stmt.src, Phi):
                        # a phi passes the earlier definitions through
                        live &= ~written
                live |= gen_of(key, stmt_idx)
            return live

        def live_out(key) -> int:
            out = 0
            for succ in succs.get(key, ()):
                out |= live_in.get(succ, 0)
            return out

        live_in = dict.fromkeys(blocks, 0)
        worklist = list(blocks)
        while worklist:
            key = worklist.pop()
            new_in = transfer(key, live_out(key), False)
            if new_in != live_in[key]:
                live_in[key] = new_in
                worklist.extend(preds[key])
        for key in blocks:
            transfer(key, live_out(key), True)

    # 1. the slots the caller still needs after each call
    call_locs = {(key, stmt_idx) for key, block_calls in calls.items() for stmt_idx, _ in block_calls}
    live_after: dict = {}

    def own_reads(key, stmt_idx) -> int:
        out = 0
        for off, size in reads_at[key].get(stmt_idx, ()):
            out |= mask(off, off + size)
        return out

    def record(key, stmt_idx, live):
        if (key, stmt_idx) in call_locs:
            live_after[(key, stmt_idx)] = live

    solve(own_reads, on_stmt=record)

    # 2. the outgoing-argument area of each call
    area: dict = {}
    for key, block_calls in calls.items():
        for stmt_idx, call in block_calls:
            start = call.tags.get(VARIADIC_STACK_ARGS_TAG)
            if start is None:
                area[(key, stmt_idx)] = mask(lo, hi)
                continue
            live = live_after.get((key, stmt_idx), 0)
            local_offsets = {off for off in address_taken if off >= start}
            local_offsets |= {points[bit] for bit in range(live.bit_length()) if live >> bit & 1 and points[bit] >= start}
            end = outgoing_area_end(start, local_offsets)
            area[(key, stmt_idx)] = mask(start, hi if end is None else end)

    kept: set[int] = set()
    solve(lambda key, stmt_idx: area.get((key, stmt_idx), 0), on_def=lambda dst: kept.add(dst.varid))
    return kept
