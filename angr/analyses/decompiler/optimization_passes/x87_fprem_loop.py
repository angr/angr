from __future__ import annotations

from typing import NamedTuple

from angr.ailment import AILBlockViewer, Block
from angr.ailment.block_walker import _ExprHandled
from angr.ailment.expression import BinaryOp, Const, DirtyExpression, Expression, Insert, Phi, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label
from angr.analyses.decompiler.block_walkers import HasCallExprWalker, HasCallNotification
from angr.analyses.decompiler.x87_fsw import FSW_C2, SOURCE_FPREM, SOURCE_FPREM1, evaluate_over_fsw
from angr.code_location import AILCodeLocation
from angr.utils.ail import dirty_has_side_effects, is_phi_assignment
from angr.utils.ssa import get_vvar_uselocs

from .optimization_pass import OptimizationPass, OptimizationPassStage

_PREM_SOURCES = {"PRem": SOURCE_FPREM, "PRem1": SOURCE_FPREM1}


class _FpremLoop(NamedTuple):
    block: Block
    exit_target: Const
    exit_idx: int | None


class _SideEffectWalker(HasCallExprWalker):
    """Raises HasCallNotification on calls and on dirty helpers with side effects."""

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if dirty_has_side_effects(expr):
            raise HasCallNotification
        return super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)


class _VVarRefs(AILBlockViewer):
    """Collects the virtual variables an expression reads, skipping the fprem results of the current iteration."""

    def __init__(self, prem_operands: tuple[Expression, Expression], source: str):
        super().__init__()
        self.prem_operands = prem_operands
        self.source = source
        self.varids: set[int] = set()

    def _is_fprem(self, operands) -> bool:
        return len(operands) == 2 and all(a.likes(b) for a, b in zip(operands, self.prem_operands, strict=True))

    def _enter_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr, BinaryOp) and _PREM_SOURCES.get(expr.op) == self.source and self._is_fprem(expr.operands):
            return _ExprHandled(None)
        if isinstance(expr, DirtyExpression) and expr.callee == self.source and self._is_fprem(expr.operands):
            return _ExprHandled(None)
        if isinstance(expr, VirtualVariable):
            self.varids.add(expr.varid)
        return super()._enter_expr(expr_idx, expr, stmt_idx, stmt, block)


class X87FpremLoopSimplifier(OptimizationPass):
    """
    Collapse the x87 remainder loop ``L: fprem[1]; fnstsw ax; sahf; jp L`` into a single fmod() / remainder().

    fprem and fprem1 only reduce the exponent difference by up to 63 per step and set C2 while the remainder is
    partial; the loop repeats them until C2 is clear, which yields the complete IEEE remainder. The self-loop block is
    turned into a straight-line block: PRem/PRem1 already stand for the complete operation, and C2 is clear when the
    loop exits. The status intrinsic stays only where something after the loop reads its quotient bits.
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Collapse x87 fprem/fprem1 loops"
    DESCRIPTION = (__doc__ or "").strip()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        assert self._graph is not None
        loops = [loop for block in self._graph if (loop := self._match(block)) is not None]
        return bool(loops), {"loops": loops}

    def _analyze(self, cache=None):
        if not cache:
            return
        for loop in cache["loops"]:
            self._collapse(loop)

    def _match(self, block: Block) -> _FpremLoop | None:  # pylint:disable=too-many-return-statements
        assert self._graph is not None
        if not block.statements or not self._graph.has_edge(block, block) or self._graph.out_degree(block) != 2:
            return None
        cond_jump = block.statements[-1]
        if not (
            isinstance(cond_jump, ConditionalJump)
            and isinstance(cond_jump.true_target, Const)
            and isinstance(cond_jump.false_target, Const)
        ):
            return None
        here = block.addr, block.idx
        true_target = cond_jump.true_target.value, cond_jump.true_target_idx
        false_target = cond_jump.false_target.value, cond_jump.false_target_idx
        if (true_target == here) == (false_target == here):
            return None
        loop_if_true = true_target == here

        # phi dst varid -> the vvar it takes from the back edge
        back_srcs: dict[int, int | None] = {}
        defs: dict[int, Expression] = {}
        prem: BinaryOp | None = None
        prem_dst: VirtualVariable | None = None
        walker = _SideEffectWalker()
        for stmt in block.statements[:-1]:
            if isinstance(stmt, Label):
                continue
            if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)):
                return None
            if is_phi_assignment(stmt):
                assert isinstance(stmt.src, Phi)
                back = [vvar for src, vvar in stmt.src.src_and_vvars if src == here]
                if len(back) != 1:
                    return None
                back_srcs[stmt.dst.varid] = back[0].varid if back[0] is not None else None
                continue
            try:
                walker.walk_statement(stmt, block)
            except HasCallNotification:
                return None
            defs[stmt.dst.varid] = stmt.src
            if isinstance(stmt.src, BinaryOp) and stmt.src.op in _PREM_SOURCES:
                if prem is not None:
                    return None
                prem, prem_dst = stmt.src, stmt.dst
        if prem is None or prem_dst is None:
            return None

        x, d = prem.operands
        source = _PREM_SOURCES[prem.op]
        # x is the remainder carried around the loop; the divisor is loop-invariant
        if not (isinstance(x, VirtualVariable) and back_srcs.get(x.varid) == prem_dst.varid):
            return None
        if self._reads(d, (x, d), source, defs) & (back_srcs.keys() | defs.keys()):
            return None

        # the loop repeats exactly while C2 is set
        table = evaluate_over_fsw([cond_jump.condition], defs)
        if (
            table is None
            or table.source != source
            or not all(a.likes(b) for a, b in zip(table.operands, (x, d), strict=True))
        ):
            return None
        for outcome, (value,) in table.values.items():
            if ((value != 0) == loop_if_true) != bool(outcome & FSW_C2):
                return None

        # values used after the loop must be those of a single (complete) iteration
        uses = get_vvar_uselocs(b for b in self._graph if b is not block)
        for varid in back_srcs:
            if varid == x.varid:
                # a propagated copy of the last fprem (fmod(x, d) after the loop) is fine
                if not all(self._only_in_fprem(loc, x.varid, (x, d), source) for _, loc in uses.get(varid, ())):
                    return None
            elif varid in uses:
                return None
        for varid, expr in defs.items():
            if varid not in uses:
                continue
            phi_varid = next((p for p, b in back_srcs.items() if b == varid), None)
            if self._loop_carried_reads(expr, phi_varid, (x, d), source, defs, back_srcs):
                return None
        if loop_if_true:
            return _FpremLoop(block, cond_jump.false_target, cond_jump.false_target_idx)
        return _FpremLoop(block, cond_jump.true_target, cond_jump.true_target_idx)

    def _only_in_fprem(
        self, loc: AILCodeLocation, varid: int, prem_operands: tuple[Expression, Expression], source: str
    ) -> bool:
        block = self._blocks_by_addr_and_idx.get((loc.addr, loc.block_idx))
        if block is None:
            return False
        refs = _VVarRefs(prem_operands, source)
        refs.walk_statement(block.statements[loc.stmt_idx], block, loc.stmt_idx)
        return varid not in refs.varids

    @staticmethod
    def _reads(
        expr: Expression, prem_operands: tuple[Expression, Expression], source: str, defs: dict[int, Expression]
    ) -> set[int]:
        """Variables expr reads, through the definitions in the loop block."""
        result: set[int] = set()
        worklist = [expr]
        seen: set[int] = set()
        while worklist:
            refs = _VVarRefs(prem_operands, source)
            refs.walk_expression(worklist.pop())
            for varid in refs.varids - seen:
                seen.add(varid)
                result.add(varid)
                if varid in defs:
                    worklist.append(defs[varid])
        return result

    def _loop_carried_reads(
        self,
        expr: Expression,
        phi_varid: int | None,
        prem_operands: tuple[Expression, Expression],
        source: str,
        defs: dict[int, Expression],
        back_srcs: dict[int, int | None],
    ) -> bool:
        """
        Whether expr depends on a value of an earlier iteration. A partial overwrite of its own loop-carried variable
        (eax after ``fnstsw ax``) is fine: the bits it keeps are the same in every iteration.
        """
        if phi_varid is not None:
            values: list[Expression] = []
            base = expr
            while True:
                if isinstance(base, VirtualVariable) and base.varid in defs:
                    base = defs[base.varid]
                elif isinstance(base, Insert):
                    values.append(base.value)
                    base = base.base
                else:
                    break
            if isinstance(base, VirtualVariable) and base.varid == phi_varid:
                return any(self._reads(v, prem_operands, source, defs) & back_srcs.keys() for v in values)
        return bool(self._reads(expr, prem_operands, source, defs) & back_srcs.keys())

    def _collapse(self, loop: _FpremLoop) -> None:
        block = loop.block
        here = block.addr, block.idx
        statements = []
        for stmt in block.statements[:-1]:
            if is_phi_assignment(stmt):
                assert isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)
                srcs = [(src, vvar) for src, vvar in stmt.src.src_and_vvars if src != here]
                if len(srcs) == 1 and srcs[0][1] is not None:
                    stmt = Assignment(stmt.idx, stmt.dst, srcs[0][1], **stmt.tags, dephi=True)
                else:
                    stmt = Assignment(
                        stmt.idx, stmt.dst, Phi(stmt.src.idx, stmt.src.bits, srcs, **stmt.src.tags), **stmt.tags
                    )
            statements.append(stmt)
        last = block.statements[-1]
        statements.append(Jump(last.idx, loop.exit_target, target_idx=loop.exit_idx, **last.tags))
        new_block = Block(block.addr, block.original_size, statements=statements, idx=block.idx)
        self._update_block(block, new_block)
        assert self.out_graph is not None
        if self.out_graph.has_edge(new_block, new_block):
            self.out_graph.remove_edge(new_block, new_block)
