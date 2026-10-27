from __future__ import annotations

from collections import deque

import networkx

from angr.ailment import AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    DirtyExpression,
    Expression,
    FunctionLikeMacro,
    Load,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import CAS, ConditionalJump, Jump, Return, Statement, Store
from angr.utils.ail import dirty_has_side_effects

from .block_walkers import PURE_INTRINSIC_CALLS

# (top, addrs): top is False -> addrs are the live bytes; top is True -> every byte is live except addrs
Liveness = tuple[bool, frozenset[int]]

_NOTHING_LIVE: Liveness = (False, frozenset())
_ALL_LIVE: Liveness = (True, frozenset())


def _is_stack_address(expr: Expression) -> bool:
    if isinstance(expr, StackBaseOffset):
        return True
    if isinstance(expr, UnaryOp) and expr.op == "Reference":
        return isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack
    if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"}:
        return _is_stack_address(expr.operands[0]) or (expr.op == "Add" and _is_stack_address(expr.operands[1]))
    return False


def _const_addr(expr: Expression) -> int | None:
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value
    return None


class _GlobalReadCollector(AILBlockViewer):
    """
    Collects the global memory a statement may read, and whether it has side effects beyond its own store.
    """

    def __init__(self):
        super().__init__()
        self.reads_all = False
        self.has_side_effects = False
        self.read_bytes: set[int] = set()

    def reset(self) -> None:
        self.reads_all = False
        self.has_side_effects = False
        self.read_bytes = set()

    def _read(self, addr: Expression, size: int) -> None:
        base = _const_addr(addr)
        if base is not None and size > 0:
            self.read_bytes.update(range(base, base + size))
        elif not _is_stack_address(addr):
            self.reads_all = True

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._read(expr.addr, expr.size)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None):
        size = stmt.data_lo.size * (2 if stmt.data_hi is not None else 1)
        self._read(stmt.addr, size)
        self.has_side_effects = True
        super()._handle_CAS(stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if not (isinstance(expr.target, str) and expr.target in PURE_INTRINSIC_CALLS):
            # the callee may read any global
            self.reads_all = True
            self.has_side_effects = True
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_FunctionLikeMacro(self, expr_idx, expr: FunctionLikeMacro, stmt_idx, stmt, block):
        self.reads_all = True
        self.has_side_effects = True
        super()._handle_FunctionLikeMacro(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if dirty_has_side_effects(expr):
            self.reads_all = True
            self.has_side_effects = True
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)


class _StmtEffect:
    __slots__ = ("candidate", "kill", "read_bytes", "reads_all")

    def __init__(self, kill: frozenset[int], read_bytes: frozenset[int], reads_all: bool, candidate: bool):
        self.kill = kill
        self.read_bytes = read_bytes
        self.reads_all = reads_all
        self.candidate = candidate


def _join(a: Liveness, b: Liveness) -> Liveness:
    a_top, a_set = a
    b_top, b_set = b
    if not a_top and not b_top:
        return False, a_set | b_set
    if a_top and b_top:
        return True, a_set & b_set
    if a_top:
        return True, a_set - b_set
    return True, b_set - a_set


def _transfer(live: Liveness, effect: _StmtEffect) -> Liveness:
    top, addrs = live
    if effect.kill:
        addrs = addrs | effect.kill if top else addrs - effect.kill
    if effect.reads_all:
        return _ALL_LIVE
    if effect.read_bytes:
        addrs = addrs - effect.read_bytes if top else addrs | effect.read_bytes
    return top, addrs


def _is_dead(live: Liveness, written: frozenset[int]) -> bool:
    top, addrs = live
    if top:
        return written <= addrs
    return not (written & addrs)


def _stmt_effect(stmt: Statement, collector: _GlobalReadCollector) -> _StmtEffect:
    collector.reset()
    collector.walk_statement(stmt)
    kill: frozenset[int] = frozenset()
    candidate = False
    if isinstance(stmt, Store) and stmt.guard is None and stmt.size > 0:
        base = _const_addr(stmt.addr)
        if base is not None:
            kill = frozenset(range(base, base + stmt.size))
            candidate = not collector.has_side_effects
    return _StmtEffect(kill, frozenset(collector.read_bytes), collector.reads_all, candidate)


def _exit_liveness(block: Block, successors: list[Block]) -> Liveness | None:
    """
    Liveness contributed by control flow that leaves the function from the end of this block.
    """
    last = block.statements[-1] if block.statements else None
    if not successors:
        # leaving through a return makes no global live; any other exit (tail jump, unresolved jump) may read anything
        return _NOTHING_LIVE if isinstance(last, Return) else _ALL_LIVE
    succ_addrs = {succ.addr for succ in successors}
    if isinstance(last, Jump):
        targets = [last.target]
    elif isinstance(last, ConditionalJump):
        targets = [t for t in (last.true_target, last.false_target) if t is not None]
    else:
        return None
    for target in targets:
        addr = _const_addr(target)
        if addr is not None and addr not in succ_addrs:
            return _ALL_LIVE
    return None


def find_dead_global_stores(
    func_graph: networkx.DiGraph, blocks: dict[Block, Block] | None = None
) -> dict[tuple[int, int | None], set[int]]:
    """
    Find stores to constant addresses whose bytes are never read before being overwritten or the function returns.

    Backward may-liveness over global memory bytes. A load from a constant address reads exactly those bytes; a load
    through any other non-stack address, a call, a function-like macro, or a side-effecting dirty helper may read every
    global. Only unguarded stores to constant addresses kill. Returning from the function reads nothing: that is the
    assumption ``allow_global_dead_ass_elim`` opts into. Leaving the function in any other way reads everything.

    :param func_graph:  The function graph.
    :param blocks:      Maps graph nodes to their up-to-date blocks, if any.
    :return:            Statement indices of dead stores, keyed by (block addr, block idx).
    """
    current = (lambda node: blocks.get(node, node)) if blocks else (lambda node: node)

    collector = _GlobalReadCollector()
    effects: dict[Block, list[_StmtEffect]] = {}
    exit_live: dict[Block, Liveness | None] = {}
    for node in func_graph:
        block = current(node)
        effects[node] = [_stmt_effect(stmt, collector) for stmt in block.statements]
        exit_live[node] = _exit_liveness(block, [current(succ) for succ in func_graph.successors(node)])

    if not any(effect.candidate for node_effects in effects.values() for effect in node_effects):
        return {}

    live_in: dict[Block, Liveness] = {}

    def _live_out(node) -> Liveness:
        live = exit_live[node]
        if live is None:
            live = _NOTHING_LIVE
        for succ in func_graph.successors(node):
            if succ in live_in:
                live = _join(live, live_in[succ])
        return live

    worklist = deque(func_graph)
    in_worklist = set(worklist)
    while worklist:
        node = worklist.popleft()
        in_worklist.discard(node)
        live = _live_out(node)
        for effect in reversed(effects[node]):
            live = _transfer(live, effect)
        if live_in.get(node) == live:
            continue
        live_in[node] = live
        for pred in func_graph.predecessors(node):
            if pred not in in_worklist:
                worklist.append(pred)
                in_worklist.add(pred)

    dead: dict[tuple[int, int | None], set[int]] = {}
    for node in func_graph:
        block = current(node)
        live = _live_out(node)
        for stmt_idx in range(len(effects[node]) - 1, -1, -1):
            effect = effects[node][stmt_idx]
            if effect.candidate and _is_dead(live, effect.kill):
                dead.setdefault((block.addr, block.idx), set()).add(stmt_idx)
            live = _transfer(live, effect)
    return dead
