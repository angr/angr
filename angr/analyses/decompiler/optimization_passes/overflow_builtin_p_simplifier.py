from __future__ import annotations

from angr.ailment import Expr
from angr.analyses.decompiler.structuring.structurer_nodes import (
    ConditionNode,
    CascadingConditionNode,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage


# Maps standalone overflow macros to their predicate-only builtin equivalents.
# __CFADD__ is intentionally excluded — carry flag has no _p builtin.
_OF_P_MAP = {
    "__OFADD__": "__builtin_add_overflow_p",
    "__OFMUL__": "__builtin_mul_overflow_p",
}


def _replace_of_p(expr):
    """
    Recursively replace ``__OFADD__``/``__OFMUL__`` Call nodes with
    ``__builtin_add_overflow_p``/``__builtin_mul_overflow_p``.

    The third argument is a zero constant with the same bit-width as the first operand,
    conveying the type for the overflow check (``(typeof(a))0``).

    Returns the original expression unchanged if no replacement was made.
    """
    if isinstance(expr, Expr.Call) and isinstance(expr.target, str) and expr.target in _OF_P_MAP:
        if not expr.args or len(expr.args) < 2:
            return expr
        builtin = _OF_P_MAP[expr.target]
        a = expr.args[0]
        tags = expr.tags or {}
        # The third argument conveys the type for the overflow check.
        # Signedness comes from the overflow_signed tag set by the ccall rewriter
        # (signed for ADD/SMUL overflow, unsigned for UMUL overflow).
        # Tag the Const so the C codegen can emit the correct cast even after
        # EvaluateConstConversions folds any wrapping Convert away.
        is_signed = tags.get("overflow_signed", False)
        zero_tags = {**tags, "overflow_p_signed": is_signed}
        zero = Expr.Const(None, None, 0, a.bits, **zero_tags)
        return Expr.Call(expr.idx, builtin, args=[expr.args[0], expr.args[1], zero], bits=expr.bits, **tags)

    # Convert is a subclass of UnaryOp — check it first
    if isinstance(expr, Expr.Convert):
        new_op = _replace_of_p(expr.operand)
        if new_op is not expr.operand:
            return Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_op, **(expr.tags or {}))
        return expr

    if isinstance(expr, Expr.UnaryOp):
        new_op = _replace_of_p(expr.operand)
        if new_op is not expr.operand:
            return Expr.UnaryOp(expr.idx, expr.op, new_op, bits=expr.bits, **(expr.tags or {}))
        return expr

    if isinstance(expr, Expr.BinaryOp):
        new_ops = [_replace_of_p(op) for op in expr.operands]
        if any(n is not o for n, o in zip(new_ops, expr.operands)):
            return Expr.BinaryOp(expr.idx, expr.op, new_ops, expr.signed, bits=expr.bits, **(expr.tags or {}))
        return expr

    return expr


class OverflowBuiltinPredicateWalker(SequenceWalker):
    """Walk the structured AST replacing ``__OFADD__``/``__OFMUL__`` with ``__builtin_*_overflow_p``."""

    def __init__(self):
        super().__init__(force_forward_scan=True, update_seqnode_in_place=False)
        self.changed = False

    def _handle_Condition(self, node, **kwargs):
        new_true = self._handle(node.true_node, parent=node, index=0) if node.true_node is not None else None
        new_false = self._handle(node.false_node, parent=node, index=1) if node.false_node is not None else None

        new_cond = None
        if node.condition is not None:
            replaced = _replace_of_p(node.condition)
            if replaced is not node.condition:
                new_cond = replaced
                self.changed = True

        if new_true is None and new_false is None and new_cond is None:
            return None

        return ConditionNode(
            node.addr,
            node.reaching_condition,
            new_cond if new_cond is not None else node.condition,
            new_true if new_true is not None else node.true_node,
            false_node=new_false if new_false is not None else node.false_node,
        )

    def _handle_CascadingCondition(self, node, **kwargs):
        conds_changed = False
        new_cond_and_nodes = []
        for index, (cond, child_node) in enumerate(node.condition_and_nodes):
            new_child = self._handle(child_node, parent=node, index=index)
            replaced_cond = _replace_of_p(cond) if cond is not None else cond
            cond_replaced = replaced_cond is not cond
            if cond_replaced:
                self.changed = True
            if new_child is not None or cond_replaced:
                conds_changed = True
                new_cond_and_nodes.append(
                    (
                        replaced_cond if cond_replaced else cond,
                        new_child if new_child is not None else child_node,
                    )
                )
            else:
                new_cond_and_nodes.append((cond, child_node))

        new_else = None
        if node.else_node is not None:
            new_else = self._handle(node.else_node, parent=node, index=-1)

        if conds_changed or new_else is not None:
            return CascadingConditionNode(
                node.addr,
                new_cond_and_nodes if conds_changed else node.condition_and_nodes,
                else_node=new_else if new_else is not None else node.else_node,
            )
        return None


class OverflowBuiltinPredicateSimplifier(SequenceOptimizationPass):
    """
    Rewrites standalone ``__OFADD__``/``__OFMUL__`` calls into
    ``__builtin_add_overflow_p``/``__builtin_mul_overflow_p`` builtins.

    Runs after :class:`OverflowBuiltinSimplifier` to catch leftover overflow
    macro calls that have no paired arithmetic expression nearby.

    .. note::
        Disabling this pass will leave IDA-style ``__OFADD__``/``__OFMUL__``
        macros in the decompiled output when no paired arithmetic is found.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Simplify standalone overflow checks to __builtin_*_overflow_p"
    DESCRIPTION = "Rewrites leftover __OFADD__/__OFMUL__ calls into predicate-only __builtin_*_overflow_p builtins"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return bool(self.seq is not None and self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = OverflowBuiltinPredicateWalker()
        result = walker.walk(self.seq)
        self.out_seq = result if result is not None else self.seq
