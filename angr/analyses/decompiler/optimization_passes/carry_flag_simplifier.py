from __future__ import annotations

from angr.ailment import Expr
from angr.analyses.decompiler.structuring.structurer_nodes import (
    ConditionNode,
    CascadingConditionNode,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage


def _replace_cfadd(expr):
    """
    Recursively replace ``__CFADD__(a, b)`` with ``(a + b) <u a``
    (unsigned less-than — the standard C carry-detection idiom).

    Returns the original expression unchanged if no replacement was made.
    """
    if isinstance(expr, Expr.Call) and isinstance(expr.target, str) and expr.target == "__CFADD__":
        if not expr.args or len(expr.args) < 2:
            return expr
        a, b = expr.args[0], expr.args[1]
        tags = expr.tags or {}
        add_expr = Expr.BinaryOp(None, "Add", [a, b], False, bits=a.bits, **tags)
        return Expr.BinaryOp(expr.idx, "CmpLT", [add_expr, a], False, bits=expr.bits, **tags)

    # Convert is a subclass of UnaryOp — check it first
    if isinstance(expr, Expr.Convert):
        new_op = _replace_cfadd(expr.operand)
        if new_op is not expr.operand:
            return Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_op, **(expr.tags or {}))
        return expr

    if isinstance(expr, Expr.UnaryOp):
        new_op = _replace_cfadd(expr.operand)
        if new_op is not expr.operand:
            return Expr.UnaryOp(expr.idx, expr.op, new_op, bits=expr.bits, **(expr.tags or {}))
        return expr

    if isinstance(expr, Expr.BinaryOp):
        new_ops = [_replace_cfadd(op) for op in expr.operands]
        if any(n is not o for n, o in zip(new_ops, expr.operands)):
            return Expr.BinaryOp(expr.idx, expr.op, new_ops, expr.signed, bits=expr.bits, **(expr.tags or {}))
        return expr

    return expr


class CarryFlagWalker(SequenceWalker):
    """Walk the structured AST replacing ``__CFADD__(a, b)`` with ``(a + b) <u a``."""

    def __init__(self):
        super().__init__(force_forward_scan=True, update_seqnode_in_place=False)
        self.changed = False

    def _handle_Condition(self, node, **kwargs):
        new_true = self._handle(node.true_node, parent=node, index=0) if node.true_node is not None else None
        new_false = self._handle(node.false_node, parent=node, index=1) if node.false_node is not None else None

        new_cond = None
        if node.condition is not None:
            replaced = _replace_cfadd(node.condition)
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
            replaced_cond = _replace_cfadd(cond) if cond is not None else cond
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


class CarryFlagSimplifier(SequenceOptimizationPass):
    """
    Rewrites ``__CFADD__(a, b)`` into the equivalent C expression
    ``(a + b) < a`` (unsigned comparison).

    This is the standard C idiom for detecting unsigned addition carry,
    and matches the original source pattern that the compiler turned into
    an ``add; jb`` sequence.

    .. note::
        Disabling this pass will leave IDA-style ``__CFADD__`` macros
        in the decompiled output.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Simplify carry flag checks to C expressions"
    DESCRIPTION = "Rewrites __CFADD__(a, b) into (a + b) < a (unsigned comparison)"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return bool(self.seq is not None and self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = CarryFlagWalker()
        result = walker.walk(self.seq)
        self.out_seq = result if result is not None else self.seq
