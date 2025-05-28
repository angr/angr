from __future__ import annotations
from typing import TYPE_CHECKING
from collections import defaultdict

import networkx

from angr.ailment import AILBlockWalker, Block
from angr.ailment.statement import ConditionalJump, Statement, Assignment
from angr.ailment.expression import Const, BinaryOp, VirtualVariable

from angr.analyses.decompiler.utils import first_nonlabel_nonphi_statement
from angr.utils.graph import dominates
from angr.utils.timing import timethis
from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from angr.analyses.s_reaching_definitions import SRDAModel


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
        self.abort = False

    def walk(self, block: Block):
        self._new_block = None
        super().walk(block)
        return self._new_block

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Block):  # type: ignore
        if self.abort:
            return

        if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid == self.vvar_id:
            # we see the assignment of this virtual variable; this is the original block that creates this variable
            # and checks if this variable is equal to a constant value. as such, we stop processing this block.
            # an example appears in binary 1de5cda760f9ed80bb6f4a35edcebc86ccec14c49cf4775ddf2ffc3e05ff35f4, function
            # 0x4657C0, blocks 0x465bd6 and 0x465a5c
            self.abort = True
            return

        r = super()._handle_stmt(stmt_idx, stmt, block)
        if r is not None:
            # replace the original statement
            if self._new_block is None:
                self._new_block = block.copy()
            self._new_block.statements[stmt_idx] = r

    def _handle_VirtualVariable(  # type: ignore
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ) -> Const | None:
        if expr.varid == self.vvar_id and not (
            isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid == self.vvar_id
        ):
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

        # group cconds according to their sources
        cconds_by_src: dict[tuple[int, int | None], list[ConstantCondition]] = {}
        for ccond in cconds:
            src = ccond.block_addr, ccond.block_idx
            if src not in cconds_by_src:
                cconds_by_src[src] = []
            cconds_by_src[src].append(ccond)

        # eliminate sources with more than one in-edges; this is because the condition may not hold on all in-edges!
        for src in list(cconds_by_src):
            block = self._get_block(src[0], idx=src[1])
            if block is not None and block in self._graph and self._graph.in_degree[block] > 1:
                del cconds_by_src[src]

        # eliminate conflicting conditions
        for src in list(cconds_by_src):
            cconds = cconds_by_src[src]
            vvar_id_to_values = defaultdict(set)
            ccond_dict = {}  # keyed by vvar_id; used for deduplication
            for ccond in cconds:
                vvar_id_to_values[ccond.vvar_id].add(ccond.value)
                ccond_dict[ccond.vvar_id] = ccond
            new_cconds = []
            for vid, vvalues in vvar_id_to_values.items():
                if len(vvalues) == 1:
                    new_cconds.append(ccond_dict[vid])
            if new_cconds:
                cconds_by_src[src] = new_cconds
            else:
                del cconds_by_src[src]

        if not cconds_by_src:
            return False, None
        return True, {"cconds_by_src": cconds_by_src}

    @timethis
    def _analyze(self, cache=None):
        if not cache or cache.get("cconds_by_src", None) is None:
            return
        cconds_by_src = cache["cconds_by_src"]

        if not cconds_by_src:
            return

        # calculate a dominance frontier for each block
        entry_node_addr, entry_node_idx = self.entry_node_addr
        entry_node = self._get_block(entry_node_addr, idx=entry_node_idx)
        idoms = networkx.algorithms.immediate_dominators(self._graph, entry_node)
        rda: SRDAModel = self.project.analyses.SReachingDefinitions(self._func, func_graph=self._graph).model

        for src, cconds in cconds_by_src.items():
            head_block = self._get_block(src[0], idx=src[1])
            if head_block is None:
                continue

            for ccond in cconds:
                for _, loc in rda.all_vvar_uses[ccond.vvar_id]:
                    loc_block = self._get_block(loc.block_addr, idx=loc.block_idx)
                    if loc_block is None:
                        continue
                    if dominates(idoms, head_block, loc_block):
                        # the constant condition dominates the use site
                        walker = CCondPropBlockWalker(ccond.vvar_id, ccond.value)
                        new_block = walker.walk(loc_block)
                        if new_block is not None:
                            self._update_block(loc_block, new_block)

    @timethis
    def _find_const_conditions(self) -> list[ConstantCondition]:
        cconds = []

        for block in self._graph:
            if block.statements:
                last_stmt = block.statements[-1]
                if (
                    isinstance(last_stmt, ConditionalJump)
                    and isinstance(last_stmt.true_target, Const)
                    and isinstance(last_stmt.false_target, Const)
                ):
                    self._extract_const_condition_from_stmt(last_stmt, cconds)
                else:
                    # also check the first non-phi statement; rep stos may generate blocks whose conditional checks
                    # are at the beginning of the block

                    # we could have used is_head_controlled_loop_block, but at this point the block is simplified enough
                    # that the first non-label, non-phi statement must be a ConditionalJump that controls the execution
                    # of the loop body, so the following logic should work fine.

                    first_stmt = first_nonlabel_nonphi_statement(block)
                    if (
                        first_stmt is not last_stmt
                        and isinstance(first_stmt, ConditionalJump)
                        and isinstance(first_stmt.true_target, Const)
                        and isinstance(first_stmt.false_target, Const)
                    ):
                        self._extract_const_condition_from_stmt(first_stmt, cconds)

        return cconds

    @staticmethod
    def _extract_const_condition_from_stmt(stmt: ConditionalJump, cconds: list[ConstantCondition]) -> None:
        if isinstance(stmt.condition, BinaryOp):
            cond = stmt.condition
            op = cond.op
            op0, op1 = cond.operands
            if isinstance(op0, Const):
                op0, op1 = op1, op0
            if isinstance(op0, VirtualVariable) and isinstance(op1, Const) and op1.is_int:
                if op == "CmpEQ":
                    ccond = ConstantCondition(
                        op0.varid, op1, stmt.true_target.value, stmt.true_target_idx  # type: ignore
                    )
                    cconds.append(ccond)
                elif op == "CmpNE":
                    ccond = ConstantCondition(
                        op0.varid, op1, stmt.false_target.value, stmt.false_target_idx  # type: ignore
                    )
                    cconds.append(ccond)
