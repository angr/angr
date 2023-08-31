# pylint:disable=unnecessary-pass
import logging
from typing import Optional, Any, TYPE_CHECKING

from ailment.statement import ConditionalJump, Assignment, Statement
from ailment.expression import Const, ITE, Expression

from ....analyses import ReachingDefinitionsAnalysis
from ....code_location import CodeLocation
from ..region_walker import RegionWalker
from ..ail_simplifier import AILBlockWalker
from ..condition_processor import ConditionProcessor
from ..structuring.structurer_nodes import EmptyBlockNotice
from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from ailment import Block as AILBlock


_l = logging.getLogger(__name__)


class NodeFoundNotification(Exception):
    """
    A notification that the target node has been found.
    """

    pass


class BlockLocator(RegionWalker):
    """
    Recursively locate block in a GraphRegion instance.

    It might be reasonable to move this class into its own file.
    """

    def __init__(self, block):
        super().__init__()

        self._block = block
        self.region = None

    def walk_node(self, region, node):
        if node == self._block:
            self.region = region
            raise NodeFoundNotification()


class ExpressionReplacer(AILBlockWalker):
    """
    Replace expressions.
    """

    def __init__(self, block_addr, target_expr, callback):
        super().__init__()
        self._block_addr = block_addr
        self._target_expr = target_expr
        self._callback = callback

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Optional[Statement], block: Optional["AILBlock"]
    ) -> Any:
        if expr == self._target_expr:
            new_expr = self._callback(self._block_addr, stmt_idx, stmt.ins_addr, expr)
            return new_expr
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class ITEExprConverter(OptimizationPass):
    """
    Transform specific expressions into If-Then-Else expressions, or tertiary expressions in C when
    given a single-use expression address. Requires outside analysis to provide the target expressions.
    """

    ARCHES = ["X86", "AMD64", "ARMEL", "ARMHF", "ARMCortexM", "MIPS32", "MIPS64"]
    PLATFORMS = ["windows", "linux", "cgc"]
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = (
        "Transform single-use expressions that were assigned to in different "
        "If-Else branches into ternary expressions"
    )
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, ite_exprs=None, **kwargs):
        super().__init__(func, **kwargs)
        self._ite_exprs = ite_exprs

        if self._ite_exprs:
            self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        for ins_addr, expr in self._ite_exprs:
            for block_addr, blocks in self.blocks_by_addr.items():
                # TODO: Optimize this stupid loop
                for block in blocks:
                    if block.addr <= ins_addr < block.addr + block.original_size:
                        block_walker = ExpressionReplacer(block_addr, expr, self._convert_expr)
                        block_walker.walk(block)

    def _convert_expr(self, block_addr: int, stmt_idx: int, ins_addr: int, atom: Expression) -> Optional[Expression]:
        rda = self.project.analyses[ReachingDefinitionsAnalysis].prep()(subject=self._func, func_graph=self._graph)

        # find the corresponding definition
        defs = []
        loc = CodeLocation(block_addr, stmt_idx, ins_addr=ins_addr)
        for def_, expr in rda.all_uses.get_uses_by_location(loc, exprs=True):
            if expr == atom:
                defs.append(def_)

        if len(defs) != 2:
            return None

        # go through all blocks in the graph to find the corresponding blocks
        def_block_addrs = {defs[0].codeloc.block_addr, defs[1].codeloc.block_addr}
        blocks = []
        for node in self._graph.nodes():
            if node.addr in def_block_addrs:
                blocks.append(node)

        if len(blocks) != 2:
            return None

        #
        # are these definitions guarded by conflicting conditions? i.e., guarded by an ite?
        #

        # find their regions
        block_0 = [b for b in blocks if b.addr == defs[0].codeloc.block_addr][0]
        region_0 = self._locate_block(block_0)

        block_1 = [b for b in blocks if b.addr == defs[1].codeloc.block_addr][0]
        region_1 = self._locate_block(block_1)

        if region_0 is None or region_1 is None or region_0 != region_1:
            return None

        # we only support the typical case of `if (cond) { a = expr_0} else { a = expr_1 }`
        head = None
        for node in region_0.graph.nodes:
            if region_0.graph.in_degree[node] == 0:
                head = node
                break
        if head is None:
            return None

        if not (region_0.graph.has_edge(head, block_0) and region_0.graph.has_edge(head, block_1)):
            return None

        #
        # create the new ITE expression to replace the atom
        #

        # extract the condition from the head
        try:
            last_stmt = ConditionProcessor.get_last_statement(head)
        except EmptyBlockNotice:
            return None
        if last_stmt is None:
            return None
        if not isinstance(last_stmt, ConditionalJump):
            return None
        if not (isinstance(last_stmt.true_target, Const) and isinstance(last_stmt.false_target, Const)):
            return None

        cond = last_stmt.condition
        if last_stmt.true_target.value == block_0.addr and last_stmt.false_target.value == block_1.addr:
            pass
        elif last_stmt.true_target.value == block_1.addr and last_stmt.false_target.value == block_0.addr:
            # swap the blocks and defs
            block_0, block_1 = block_1, block_0
            defs = [defs[1], defs[0]]
        else:
            return None

        # extract expressions from both blocks
        for idx, stmt in enumerate(reversed(block_0.statements)):
            if isinstance(stmt, Assignment) and stmt.dst.likes(atom):
                expr_0 = stmt.src
                block_0_stmt_idx = len(block_0.statements) - idx - 1
                break
        else:
            return None

        for idx, stmt in enumerate(reversed(block_1.statements)):
            if isinstance(stmt, Assignment) and stmt.dst.likes(atom):
                expr_1 = stmt.src
                block_1_stmt_idx = len(block_1.statements) - idx - 1
                break
        else:
            return None

        # make sure the two assigned dst expressions are only used once
        uses_0 = rda.all_uses.get_uses(defs[0])
        if len(uses_0) != 1:
            return None
        uses_1 = rda.all_uses.get_uses(defs[1])
        if len(uses_1) != 1:
            return None

        new_expr = ITE(
            None,
            cond,
            expr_1,
            expr_0,
            ins_addr=expr_0.ins_addr,
            vex_block_addr=expr_0.vex_block_addr,
            vex_stmt_idx=expr_0.vex_stmt_idx,
        )

        # remove the two assignments
        block_0.statements = block_0.statements[0:block_0_stmt_idx] + block_0.statements[block_0_stmt_idx + 1 :]
        block_1.statements = block_1.statements[0:block_1_stmt_idx] + block_1.statements[block_1_stmt_idx + 1 :]

        return new_expr

    def _locate_block(self, block: "AILBlock"):
        locator = BlockLocator(block)
        try:
            locator.walk(self._ri.region)
        except NodeFoundNotification:
            return locator.region
        return None  # not found
