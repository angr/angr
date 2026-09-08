from __future__ import annotations

from typing import TYPE_CHECKING

import networkx

from angr.ailment.block import Block
from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import BinaryOp, Call, Const, Convert, Expression, IRegister, Register, Tmp
from angr.ailment.statement import Assignment, SideEffectStatement, Statement
from angr.calling_conventions import SimLyingRegArg
from angr.sim_type import SimTypeFloat

from .ailgraph_walker import AILGraphWalker

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.project import Project


# register state: (offset, size) -> value; a register absent from the dict has an unknown value
RegState = dict[tuple[int, int], int]


class IRegisterResolver:
    """
    Resolves ``IRegister`` (VEX GetI/PutI register-array accesses, e.g. x87 ``fpreg[ftop]``) into concrete
    ``Register`` expressions by forward-tracking constant register values across the AIL graph.

    Index registers (x87 ``ftop``) are seeded with their calling-convention initial value at the function entry.
    Calls keep the tracked index registers, except that an x87-returning callee leaves one value pushed on the FP
    stack. Accesses whose index cannot be resolved are left alone for ``IRegReplacer``.
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

    def __init__(self, project: Project, kb: KnowledgeBase, function: Function, ail_graph: networkx.DiGraph):
        self.project = project
        self.kb = kb
        self.function = function
        self.graph = ail_graph
        self._arch = project.arch
        self._ftop_key: tuple[int, int] | None = self._arch.registers.get("ftop")
        self._fpreg_base: int | None = self._arch.registers["fpreg"][0] if "fpreg" in self._arch.registers else None
        self._x87_return_cache: dict[int, bool] = {}

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
        entry_states = self._compute_entry_states()

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

    def _compute_entry_states(self) -> dict[tuple[int, int | None], RegState]:
        entry_states: dict[tuple[int, int | None], RegState] = {}
        exit_states: dict[tuple[int, int | None], RegState] = {}
        blocks_by_key = {(b.addr, b.idx): b for b in self.graph.nodes()}
        entries = [b for b in self.graph.nodes() if b.addr == self.function.addr and b.idx is None]
        if not entries:
            entries = [b for b in self.graph.nodes() if self.graph.in_degree(b) == 0]

        worklist = []
        for b in entries:
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
                    worklist.append(blocks_by_key[succ_key])
        return entry_states

    @staticmethod
    def _merge(a: RegState | None, b: RegState) -> RegState:
        if a is None:
            return dict(b)
        return {k: v for k, v in a.items() if b.get(k) == v}

    # ---- block simulation -----------------------------------------------

    def _run_block(self, block: Block, entry_state: RegState, rewrite: bool) -> tuple[RegState, Block | None]:
        regs: RegState = dict(entry_state)
        tmps: dict[int, int] = {}
        rewriter = AILBlockRewriter(update_block=False)

        def handle_ireg(expr_idx: int, expr: IRegister, stmt_idx: int, stmt: Statement | None, block_: Block | None):
            resolved = self._resolve_ireg(expr, tmps, regs)
            return resolved if resolved is not None else expr

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
                self._apply_call(stmt.expr, regs)
            return new_stmt

        rewriter.stmt_handlers[Assignment] = handle_assignment
        rewriter.stmt_handlers[SideEffectStatement] = handle_side_effect
        rewriter.expr_handlers[IRegister] = handle_ireg
        new_block = rewriter.walk(block)
        return regs, (new_block if rewrite and new_block is not block else None)

    @staticmethod
    def _write_register(regs: RegState, offset: int, size: int, value: int | None) -> None:
        for key in [k for k in regs if k[0] < offset + size and offset < k[0] + k[1]]:
            del regs[key]
        if value is not None:
            regs[(offset, size)] = value

    def _apply_call(self, call: Call, regs: RegState) -> None:
        # callee-clobbered registers become unknown; ftop survives a balanced x87 stack
        ftop = regs.get(self._ftop_key) if self._ftop_key is not None else None
        regs.clear()
        if self._ftop_key is None or ftop is None:
            return
        if (
            isinstance(call.target, Const)
            and isinstance(call.target.value, int)
            and self._callee_pushes_x87(call.target.value)
        ):
            ftop = (ftop - 1) % 8
        regs[self._ftop_key] = ftop

    def _callee_pushes_x87(self, callee_addr: int) -> bool:
        """Whether the callee returns a floating-point value on the x87 stack (st0), leaving it pushed."""
        if callee_addr in self._x87_return_cache:
            return self._x87_return_cache[callee_addr]
        result = False
        callee = self.kb.functions.function(addr=callee_addr)
        if callee is not None:
            cc = callee.calling_convention
            if cc is not None and isinstance(cc.FP_RETURN_VAL, SimLyingRegArg):
                if callee.prototype is not None:
                    result = isinstance(callee.prototype.returnty, SimTypeFloat)
                else:
                    result = self._function_writes_fpreg(callee)
        self._x87_return_cache[callee_addr] = result
        return result

    def _function_writes_fpreg(self, func: Function) -> bool:
        if self._fpreg_base is None:
            return False
        for node in func.graph.nodes():
            try:
                irsb = self.project.factory.block(node.addr, size=node.size).vex
            except Exception:  # pylint:disable=broad-exception-caught
                continue
            for stmt in irsb.statements:
                if stmt.tag == "Ist_PutI" and stmt.descr.base == self._fpreg_base:
                    return True
        return False

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
