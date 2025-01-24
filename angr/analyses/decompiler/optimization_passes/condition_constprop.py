from __future__ import annotations

import networkx

from ailment import AILBlockWalker, Block
from ailment.statement import ConditionalJump, Statement
from ailment.expression import Const, BinaryOp, VirtualVariable

from angr.analyses.decompiler.region_identifier import RegionIdentifier
from .optimization_pass import OptimizationPass, OptimizationPassStage


class ConstantCondition:
    """
    Describes an opportunity for replacing a vvar with a constant value.
    """

    def __init__(self, vvar_id: int, value: Const, block_addr: int, block_idx: int | None):
        self.vvar_id = vvar_id
        self.value = value
        self.block_addr = block_addr
        self.block_idx = block_idx

    def __repr__(self):
        return f"<ConstCond vvar_{self.vvar_id} == {self.value} since {self.block_addr:#x}-{self.block_idx}>"


class CCondPropBlockWalker(AILBlockWalker):
    """
    Block walker for ConditionConstantPropagation to replace vvars with constant values.
    """

    def __init__(self, vvar_id: int, const_value: Const):
        super().__init__()
        self._new_block: Block | None = None  # output
        self.vvar_id = vvar_id
        self.const_value = const_value

    def walk(self, block: Block):
        self._new_block = None
        super().walk(block)
        return self._new_block

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Block):  # type: ignore
        r = super()._handle_stmt(stmt_idx, stmt, block)
        if r is not None:
            # replace the original statement
            if self._new_block is None:
                self._new_block = block.copy()
            self._new_block.statements[stmt_idx] = r

    def _handle_VirtualVariable(  # type: ignore
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ) -> Const | None:
        if expr.varid == self.vvar_id:
            return Const(expr.idx, None, self.const_value.value, self.const_value.bits, **expr.tags)
        return None


class ConditionConstantPropagation(OptimizationPass):
    """
    Reason about constant propagation opportunities from conditionals and propagate constants in the graph accordingly.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
    NAME = "Propagate constants using information deduced from conditionals."
    DESCRIPTION = __doc__.strip()  # type: ignore

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        cconds = self._find_const_conditions()
        if not cconds:
            return False, None
        return True, {"cconds": cconds}

    def _analyze(self, cache=None):
        if not cache or cache.get("cconds", None) is None:  # noqa: SIM108
            cconds = self._find_const_conditions()
        else:
            cconds = cache["cconds"]

        if not cconds:
            return

        # group cconds according to their sources
        cconds_by_src: dict[tuple[int, int | None], list[ConstantCondition]] = {}
        for ccond in cconds:
            src = ccond.block_addr, ccond.block_idx
            if src not in cconds_by_src:
                cconds_by_src[src] = []
            cconds_by_src[src].append(ccond)

        # calculate a dominance frontier for each block
        entry_node_addr, entry_node_idx = self.entry_node_addr
        entry_node = self._get_block(entry_node_addr, idx=entry_node_idx)
        df = networkx.algorithms.dominance_frontiers(self._graph, entry_node)

        for src, cconds in cconds_by_src.items():
            head_block = self._get_block(src[0], idx=src[1])
            if head_block is None:
                continue
            frontier = df.get(head_block)
            if frontier is None:
                continue
            graph_slice = RegionIdentifier.slice_graph(self._graph, head_block, frontier, include_frontier=False)
            for ccond in cconds:
                walker = CCondPropBlockWalker(ccond.vvar_id, ccond.value)
                for block in graph_slice:
                    new_block = walker.walk(block)
                    if new_block is not None:
                        self._update_block(block, new_block)

    def _find_const_conditions(self) -> list[ConstantCondition]:
        cconds = []

        for block in self._graph:
            if block.statements:
                last_stmt = block.statements[-1]
                if (
                    not isinstance(last_stmt, ConditionalJump)
                    or not isinstance(last_stmt.true_target, Const)
                    or not isinstance(last_stmt.false_target, Const)
                ):
                    continue

                if isinstance(last_stmt.condition, BinaryOp):
                    cond = last_stmt.condition
                    op = cond.op
                    op0, op1 = cond.operands
                    if isinstance(op0, Const):
                        op0, op1 = op1, op0
                    if isinstance(op0, VirtualVariable) and isinstance(op1, Const) and op1.is_int:
                        if op == "CmpEQ":
                            ccond = ConstantCondition(
                                op0.varid, op1, last_stmt.true_target.value, last_stmt.true_target_idx  # type: ignore
                            )
                            cconds.append(ccond)
                        elif op == "CmpNE":
                            ccond = ConstantCondition(
                                op0.varid, op1, last_stmt.false_target.value, last_stmt.false_target_idx  # type: ignore
                            )
                            cconds.append(ccond)

        return cconds
