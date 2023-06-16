import logging
from typing import Optional, Dict, Any, Callable, TYPE_CHECKING

from ailment.block import Block as AILBlock
from ailment.statement import Statement
from ailment.expression import Expression, BinaryOp

from ..sequence_walker import SequenceWalker
from ..ail_simplifier import AILBlockWalker
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from angr.analyses.decompiler.structurer_nodes import ConditionNode, ConditionalBreakNode, LoopNode


_l = logging.getLogger(__name__)


class OuterWalker(SequenceWalker):
    """
    A sequence walker that finds nodes and invokes expression replacer to replace expressions.
    """

    def __init__(self, desc):
        super().__init__()
        self.desc: Dict[OpDescriptor, str] = desc

    def _handle_Condition(self, node: "ConditionNode", **kwargs):
        for desc, new_op in self.desc.items():
            if (
                hasattr(node.condition, "ins_addr")
                and node.condition.ins_addr == desc.ins_addr
                and node.condition.op == desc.op
            ):
                node.condition = self._swap_expr_op(new_op, node.condition)
        return super()._handle_Condition(node, **kwargs)

    def _handle_Loop(self, node: "LoopNode", **kwargs):
        for desc, new_op in self.desc.items():
            if (
                hasattr(node.condition, "ins_addr")
                and node.condition.ins_addr == desc.ins_addr
                and node.condition.op == desc.op
            ):
                node.condition = self._swap_expr_op(new_op, node.condition)
        return super()._handle_Loop(node, **kwargs)

    def _handle_ConditionalBreak(self, node: "ConditionalBreakNode", **kwargs):
        for desc, new_op in self.desc.items():
            if (
                hasattr(node.condition, "ins_addr")
                and node.condition.ins_addr == desc.ins_addr
                and node.condition.op == desc.op
            ):
                node.condition = self._swap_expr_op(new_op, node.condition)
        return super()._handle_ConditionalBreak(node, **kwargs)

    @staticmethod
    def _swap_expr_op(new_op: str, atom: Expression) -> Optional[Expression]:
        # swap
        new_expr = BinaryOp(
            atom.idx, new_op, (atom.operands[1], atom.operands[0]), atom.signed, bits=atom.bits, **atom.tags
        )
        return new_expr


class ExpressionReplacer(AILBlockWalker):
    """
    Replace expressions.
    """

    def __init__(self, block_addr, target_expr_predicate, callback):
        super().__init__()
        self._block_addr = block_addr
        self._target_expr_predicate: Callable = target_expr_predicate
        self._callback = callback

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Optional[Statement], block: Optional[AILBlock]
    ) -> Any:
        if self._target_expr_predicate(expr):
            new_expr = self._callback(self._block_addr, expr)
            return new_expr
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class OpDescriptor:
    """
    Describes a specific operator.
    """

    def __init__(self, block_addr: int, stmt_idx: int, ins_addr: int, op: str):
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.ins_addr = ins_addr
        self.op = op

    def __hash__(self):
        return hash((OpDescriptor, self.block_addr, self.stmt_idx, self.ins_addr, self.op))

    def __eq__(self, other):
        return (
            isinstance(other, OpDescriptor)
            and self.block_addr == other.block_addr
            and self.stmt_idx == other.stmt_idx
            and self.ins_addr == other.ins_addr
            and self.op == other.op
        )


class ExprOpSwapper(SequenceOptimizationPass):
    """
    Swap operands (and the operator accordingly) in a BinOp expression.
    """

    ARCHES = ["X86", "AMD64", "ARMEL", "ARMHF", "ARMCortexM", "MIPS32", "MIPS64"]
    PLATFORMS = ["windows", "linux", "cgc"]
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Swap operands of expressions as requested"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, binop_operators: Optional[Dict[OpDescriptor, str]] = None, **kwargs):
        super().__init__(func, **kwargs)
        self._expr_operators = {} if binop_operators is None else binop_operators

        if self._expr_operators:
            self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):  # pylint:disable=unused-argument
        walker = OuterWalker(self._expr_operators)
        walker.walk(self.seq)
        self.out_seq = self.seq
