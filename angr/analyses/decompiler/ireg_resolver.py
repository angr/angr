from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

import networkx

from angr.ailment.block import Block
from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import BinaryOp, Call, Const, Convert, Expression, IRegister, Register, Tmp
from angr.ailment.statement import Assignment, Return, SideEffectStatement, Statement
from angr.utils.x87 import X87StackModel

from .ailgraph_walker import AILGraphWalker

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.project import Project


# register state: (offset, size) -> value; a register absent from the dict has an unknown value
RegState = dict[tuple[int, int], int]
BlockKey = tuple[int, int | None]

# how many blocks after a call site are scanned for the first x87 stack access
MAX_CALLER_SCAN_BLOCKS = 4


class IRegisterResolver:
    """
    Resolves ``IRegister`` (VEX GetI/PutI register-array accesses, e.g. x87 ``fpreg[ftop]``) into concrete
    ``Register`` expressions by forward-tracking constant register values across the AIL graph.

    The x87 stack pointer ``ftop`` is 0 at the function entry (the ABI requires an empty x87 stack across calls).
    At a call site the callee's net effect on ``ftop`` is derived from, in order, the callee's own code, its
    prototype, and the first x87 stack access that follows the call in the caller. Blocks whose entry ``ftop``
    cannot be determined exactly (conflicting predecessors, e.g. an unbalanced path) fall back to the most common
    value among their predecessors, so that every x87 access still resolves to a concrete ``st(i)``. Reads of
    ``ftop`` outside of register-array indices (``fnstsw``) are replaced with the tracked constant.
    """

    _BINOPS = {
        "Add": lambda a, b: a + b,
        "Sub": lambda a, b: a - b,
        "Mul": lambda a, b: a * b,
        "And": lambda a, b: a & b,
        "Or": lambda a, b: a | b,
        "Xor": lambda a, b: a ^ b,
        "Shl": lambda a, b: a << b,
        "Shr": lambda a, b: a >> b,
    }

    def __init__(
        self,
        project: Project,
        kb: KnowledgeBase,
        function: Function,
        ail_graph: networkx.DiGraph,
        callee_deltas: dict[int, int | None] | None = None,
        call_st0: dict[int, int] | None = None,
    ):
        self.project = project
        self.kb = kb
        self.function = function
        self.graph = ail_graph
        self._arch = project.arch
        self._ftop_key: tuple[int, int] | None = self._arch.registers.get("ftop")
        self._fpreg_base: int | None = self._arch.registers["fpreg"][0] if "fpreg" in self._arch.registers else None
        self._fptag_base: int | None = self._arch.registers["fptag"][0] if "fptag" in self._arch.registers else None
        self._stack_model = X87StackModel(project, kb, callee_deltas=callee_deltas)
        # call instruction address -> register offset of st(0) right after the call
        self._call_st0: dict[int, int] = call_st0 if call_st0 is not None else {}
        self._caller_delta_cache: dict[tuple[BlockKey, int], int] = {}
        self._blocks_by_key: dict[BlockKey, Block] = {}

    @staticmethod
    def has_iregisters(ail_graph: networkx.DiGraph) -> bool:
        found = False

        def _handle_ireg(expr_idx: int, expr: IRegister, stmt_idx: int, stmt: Statement | None, block: Block | None):
            nonlocal found
            found = True

        viewer = AILBlockViewer(expr_handlers={IRegister: _handle_ireg})
        for block in ail_graph.nodes():
            viewer.walk(block)
            if found:
                return True
        return False

    def resolve(self) -> None:
        self._blocks_by_key = {(b.addr, b.idx): b for b in self.graph.nodes()}
        entry_states = self._compute_entry_states()
        self._fill_unknown_ftops(entry_states)

        def _handler(block: Block) -> Block | None:
            state = entry_states.get((block.addr, block.idx))
            if state is None:
                return None
            _, new_block = self._run_block(block, state, rewrite=True)
            return new_block

        AILGraphWalker(self.graph, _handler, replace_nodes=True).walk()

    # ---- dataflow -------------------------------------------------------

    def _entry_state(self) -> RegState:
        state: RegState = {}
        if self._ftop_key is not None:
            state[self._ftop_key] = 0
        return state

    def _entry_blocks(self) -> list[Block]:
        entries = [b for b in self.graph.nodes() if b.addr == self.function.addr and b.idx is None]
        if not entries:
            entries = [b for b in self.graph.nodes() if self.graph.in_degree(b) == 0]
        return entries

    def _compute_entry_states(self) -> dict[BlockKey, RegState]:
        entry_states: dict[BlockKey, RegState] = {}
        exit_states: dict[BlockKey, RegState] = {}

        worklist = []
        for b in self._entry_blocks():
            entry_states[(b.addr, b.idx)] = self._entry_state()
            worklist.append(b)

        while worklist:
            block = worklist.pop(0)
            key = (block.addr, block.idx)
            exit_state, _ = self._run_block(block, entry_states[key], rewrite=False)
            if exit_states.get(key) == exit_state:
                continue
            exit_states[key] = exit_state
            for succ in self.graph.successors(block):
                succ_key = (succ.addr, succ.idx)
                merged = self._merge(entry_states.get(succ_key), exit_state)
                if merged != entry_states.get(succ_key):
                    entry_states[succ_key] = merged
                    worklist.append(self._blocks_by_key[succ_key])
        return entry_states

    @staticmethod
    def _merge(a: RegState | None, b: RegState) -> RegState:
        if a is None:
            return dict(b)
        return {k: v for k, v in a.items() if b.get(k) == v}

    def _fill_unknown_ftops(self, entry_states: dict[BlockKey, RegState]) -> None:
        """
        Assign a fallback ftop to blocks whose exact entry ftop is unknown: the most common exit ftop among the
        predecessors (ties prefer the ABI-canonical 0), or 0 when no predecessor has one. Blocks are visited in
        reverse post-order so that fallbacks propagate along forward edges.
        """
        if self._ftop_key is None:
            return
        ftop_key = self._ftop_key
        unknown = [key for key, state in entry_states.items() if ftop_key not in state]
        if not unknown and len(entry_states) == len(self._blocks_by_key):
            return

        order: list[Block] = []
        entries = self._entry_blocks()
        for entry in entries:
            order.extend(networkx.dfs_postorder_nodes(self.graph, entry))
        seen = set(order)
        order.extend(b for b in self.graph.nodes() if b not in seen)
        order.reverse()

        exit_ftops: dict[BlockKey, int] = {}
        for block in order:
            key = (block.addr, block.idx)
            state = entry_states.get(key)
            if state is None:
                state = entry_states[key] = {}
            if ftop_key not in state:
                votes = Counter(
                    exit_ftops[(p.addr, p.idx)] for p in self.graph.predecessors(block) if (p.addr, p.idx) in exit_ftops
                )
                state[ftop_key] = min(votes, key=lambda v: (-votes[v], v % 8 != 0, v)) if votes else 0
            exit_state, _ = self._run_block(block, state, rewrite=False)
            if ftop_key in exit_state:
                exit_ftops[key] = exit_state[ftop_key]

    # ---- block simulation -----------------------------------------------

    def _run_block(self, block: Block, entry_state: RegState, rewrite: bool) -> tuple[RegState, Block | None]:
        regs: RegState = dict(entry_state)
        tmps: dict[int, int] = {}
        rewriter = AILBlockRewriter(update_block=False)

        def handle_ireg(expr_idx: int, expr: IRegister, stmt_idx: int, stmt: Statement | None, block_: Block | None):
            resolved = self._resolve_ireg(expr, tmps, regs)
            return resolved if resolved is not None else expr

        def handle_register(expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement | None, block_: Block | None):
            # fold reads of the index register itself (fnstsw) into the tracked constant
            key = (expr.reg_offset, expr.size)
            if key == self._ftop_key and key in regs:
                return Const(expr.idx, regs[key], expr.bits, **expr.tags)
            return expr

        def handle_assignment(stmt_idx: int, stmt: Assignment, block_: Block | None):
            dst = stmt.dst
            new_src = rewriter._handle_expr(1, stmt.src, stmt_idx, stmt, block_)
            new_stmt = stmt
            if isinstance(dst, IRegister):
                resolved = self._resolve_ireg(dst, tmps, regs)
                if resolved is not None or new_src is not stmt.src:
                    new_stmt = Assignment(stmt.idx, resolved if resolved is not None else dst, new_src, **stmt.tags)
            elif new_src is not stmt.src:
                new_stmt = Assignment(stmt.idx, dst, new_src, **stmt.tags)

            value = self._eval(stmt.src, tmps, regs)
            if isinstance(dst, Tmp):
                if value is not None:
                    tmps[dst.tmp_idx] = value
                else:
                    tmps.pop(dst.tmp_idx, None)
            elif isinstance(dst, Register):
                self._write_register(regs, dst.reg_offset, dst.size, value)
            return new_stmt

        def handle_side_effect(stmt_idx: int, stmt: SideEffectStatement, block_: Block | None):
            new_stmt = rewriter._handle_SideEffectStatement(stmt_idx, stmt, block_)
            if isinstance(stmt.expr, Call):
                self._apply_call(stmt.expr, regs, block, stmt_idx)
            return new_stmt

        rewriter.stmt_handlers[Assignment] = handle_assignment
        rewriter.stmt_handlers[SideEffectStatement] = handle_side_effect
        rewriter.expr_handlers[IRegister] = handle_ireg
        if rewrite:
            rewriter.expr_handlers[Register] = handle_register
        new_block = rewriter.walk(block)
        return regs, (new_block if rewrite and new_block is not block else None)

    @staticmethod
    def _write_register(regs: RegState, offset: int, size: int, value: int | None) -> None:
        for key in [k for k in regs if k[0] < offset + size and offset < k[0] + k[1]]:
            del regs[key]
        if value is not None:
            regs[(offset, size)] = value

    # ---- calls ------------------------------------------------------------

    def _apply_call(self, call: Call, regs: RegState, block: Block, stmt_idx: int) -> None:
        # callee-clobbered registers become unknown; the ABI keeps the x87 stack balanced across calls, so an
        # unknown ftop is canonical (0) after the call
        ftop = regs.get(self._ftop_key) if self._ftop_key is not None else None
        regs.clear()
        if self._ftop_key is None:
            return
        if ftop is None:
            ftop = 0
        delta = None
        if isinstance(call.target, Const) and isinstance(call.target.value, int):
            delta = self._stack_model.callee_delta(call.target.value)
        if delta is None:
            cache_key = ((block.addr, block.idx), stmt_idx)
            if cache_key not in self._caller_delta_cache:
                self._caller_delta_cache[cache_key] = self._infer_call_delta_from_caller(block, stmt_idx)
            delta = self._caller_delta_cache[cache_key]
        ftop = (ftop + delta) % 8
        regs[self._ftop_key] = ftop
        ins_addr = call.tags.get("ins_addr")
        if self._fpreg_base is not None and isinstance(ins_addr, int):
            self._call_st0[ins_addr] = self._fpreg_base + (ftop << 3)

    def _infer_call_delta_from_caller(self, block: Block, stmt_idx: int) -> int:
        """
        Infer whether a callee left a value on the x87 stack from the caller: the first x87 stack access after the
        call touching st(0) or above (relative to ftop at the return site) means it did; a push first means it did
        not. A return reached first defers to this function's own FP return.
        """
        assert self._ftop_key is not None
        probe: RegState = {self._ftop_key: 0}
        result = self._scan_block_for_x87(block, stmt_idx + 1, probe)
        if result is not None:
            return result

        visited = {(block.addr, block.idx)}
        frontier = list(self.graph.successors(block))
        scanned = 0
        while frontier and scanned < MAX_CALLER_SCAN_BLOCKS:
            succ = frontier.pop(0)
            key = (succ.addr, succ.idx)
            if key in visited:
                continue
            visited.add(key)
            scanned += 1
            result = self._scan_block_for_x87(succ, 0, dict(probe))
            if result is not None:
                return result
            frontier.extend(self.graph.successors(succ))
        return 0

    def _scan_block_for_x87(self, block: Block, start: int, regs: RegState) -> int | None:
        tmps: dict[int, int] = {}
        found: int | None = None

        def handle_ireg(expr_idx: int, expr: IRegister, stmt_idx: int, stmt: Statement | None, block_: Block | None):
            nonlocal found
            if found is None and expr.array_base in (self._fpreg_base, self._fptag_base):
                ix = self._eval(expr.reg_offset, tmps, regs)
                if ix is not None:
                    if ix >= 0x80000000:
                        ix -= 0x100000000
                    found = -1 if ix + expr.array_bias >= 0 else 0

        viewer = AILBlockViewer(expr_handlers={IRegister: handle_ireg})
        for i in range(start, len(block.statements)):
            stmt = block.statements[i]
            if isinstance(stmt, Return):
                return -1 if X87StackModel.prototype_returns_x87(self.function) else 0
            if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                return 0
            viewer.walk_statement(stmt, block, i)
            if found is not None:
                return found
            if isinstance(stmt, Assignment):
                value = self._eval(stmt.src, tmps, regs)
                if isinstance(stmt.dst, Tmp):
                    if value is not None:
                        tmps[stmt.dst.tmp_idx] = value
                    else:
                        tmps.pop(stmt.dst.tmp_idx, None)
                elif isinstance(stmt.dst, Register):
                    self._write_register(regs, stmt.dst.reg_offset, stmt.dst.size, value)
        return None

    # ---- expression evaluation --------------------------------------------

    def _eval(self, expr: Expression, tmps: dict[int, int], regs: RegState) -> int | None:
        if isinstance(expr, Const):
            return expr.value & ((1 << expr.bits) - 1) if isinstance(expr.value, int) else None
        if isinstance(expr, Tmp):
            return tmps.get(expr.tmp_idx)
        if isinstance(expr, Register):
            return regs.get((expr.reg_offset, expr.size))
        if isinstance(expr, Convert):
            v = self._eval(expr.operand, tmps, regs)
            return v & ((1 << expr.to_bits) - 1) if v is not None else None
        if isinstance(expr, BinaryOp) and expr.op in self._BINOPS:
            a = self._eval(expr.operands[0], tmps, regs)
            b = self._eval(expr.operands[1], tmps, regs)
            if a is None or b is None:
                return None
            return self._BINOPS[expr.op](a, b) & ((1 << expr.bits) - 1)
        return None

    def _resolve_ireg(self, ireg: IRegister, tmps: dict[int, int], regs: RegState) -> Register | None:
        ix = self._eval(ireg.reg_offset, tmps, regs)
        if ix is None:
            return None
        if ix >= 0x80000000:
            ix -= 0x100000000
        offset = ireg.array_base + (((ix + ireg.array_bias) % ireg.array_nElems) << ireg.array_shift)
        tags = dict(ireg.tags)
        tags["reg_name"] = self._arch.translate_register_name(offset, size=ireg.size)
        return Register(ireg.idx, offset, ireg.bits, **tags)
