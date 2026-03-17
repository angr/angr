from __future__ import annotations

from angr.ailment import Expr
from angr.analyses.decompiler.structuring.structurer_nodes import (
    ConditionNode,
    CascadingConditionNode,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage


def _replace_flag_builtins(expr):
    """
    Recursively replace flag-condition pseudo-builtins with equivalent
    C-level expressions.

    Supported builtins:

    - ``__DEC_COND_LE__(result)``   → ``(result + 1) <=s 1``
    - ``__ADD_COND_LE__(a, b)``     → ``(sext(a,N+1) + sext(b,N+1)) <=s 0``
    - ``__ADD_COND_HI__(a, b)``     → ``(a+b) <u a && (a+b) != 0``
    - ``__ADD_COND_GE__(a, b)``     → ``(sext(a,N+1) + sext(b,N+1)) >=s 0``
    - ``__ADD_COND_GT__(a, b)``     → ``(sext(a,N+1) + sext(b,N+1)) >=s 0 && (a+b) != 0``
    - ``__SBB_COND_A__(a, b, c)``   → ``zext(a,N+1) >=u (zext(b,N+1)+zext(c,N+1)) && (a-b-c) != 0``
    - ``__SBB_COND_L__(a, b, c)``   → ``sext(a,2N) <s (sext(b,2N)+zext(c,2N))``

    Returns the original expression unchanged if no replacement was made.
    """
    if isinstance(expr, Expr.Call) and isinstance(expr.target, str):
        target = expr.target
        tags = expr.tags or {}

        if target == "__DEC_COND_LE__":
            # (result + 1) <=s 1
            result = expr.args[0]
            n = result.bits
            one = Expr.Const(None, None, 1, n, **tags)
            inc = Expr.BinaryOp(None, "Add", [result, one], False, bits=n, **tags)
            return Expr.BinaryOp(expr.idx, "CmpLE", [inc, one], True, bits=expr.bits, **tags)

        if target == "__ADD_COND_LE__":
            # (sext(a, N+1) + sext(b, N+1)) <=s 0
            a, b = expr.args[0], expr.args[1]
            n = a.bits
            ext = n + 1
            a_ext = Expr.Convert(None, n, ext, True, a, **tags)
            b_ext = Expr.Convert(None, n, ext, True, b, **tags)
            s_ext = Expr.BinaryOp(None, "Add", [a_ext, b_ext], False, bits=ext, **tags)
            zero = Expr.Const(None, None, 0, ext, **tags)
            return Expr.BinaryOp(expr.idx, "CmpLE", [s_ext, zero], True, bits=expr.bits, **tags)

        if target == "__ADD_COND_HI__":
            # (a + b) <u a && (a + b) != 0
            a, b = expr.args[0], expr.args[1]
            n = a.bits
            res = Expr.BinaryOp(None, "Add", [a, b], False, bits=n, **tags)
            cf = Expr.BinaryOp(None, "CmpLT", [res, a], False, bits=1, **tags)
            zero = Expr.Const(None, None, 0, n, **tags)
            nz = Expr.BinaryOp(None, "CmpNE", [res, zero], False, bits=1, **tags)
            return Expr.BinaryOp(expr.idx, "And", [cf, nz], False, bits=expr.bits, **tags)

        if target == "__ADD_COND_GE__":
            # (sext(a, N+1) + sext(b, N+1)) >=s 0
            a, b = expr.args[0], expr.args[1]
            n = a.bits
            ext = n + 1
            a_ext = Expr.Convert(None, n, ext, True, a, **tags)
            b_ext = Expr.Convert(None, n, ext, True, b, **tags)
            s_ext = Expr.BinaryOp(None, "Add", [a_ext, b_ext], False, bits=ext, **tags)
            zero = Expr.Const(None, None, 0, ext, **tags)
            return Expr.BinaryOp(expr.idx, "CmpGE", [s_ext, zero], True, bits=expr.bits, **tags)

        if target == "__ADD_COND_GT__":
            # (sext(a, N+1) + sext(b, N+1)) >=s 0 && (a + b) != 0
            a, b = expr.args[0], expr.args[1]
            n = a.bits
            ext = n + 1
            a_ext = Expr.Convert(None, n, ext, True, a, **tags)
            b_ext = Expr.Convert(None, n, ext, True, b, **tags)
            s_ext = Expr.BinaryOp(None, "Add", [a_ext, b_ext], False, bits=ext, **tags)
            zero_ext = Expr.Const(None, None, 0, ext, **tags)
            ge = Expr.BinaryOp(None, "CmpGE", [s_ext, zero_ext], True, bits=1, **tags)
            res = Expr.BinaryOp(None, "Add", [a, b], False, bits=n, **tags)
            zero_n = Expr.Const(None, None, 0, n, **tags)
            nz = Expr.BinaryOp(None, "CmpNE", [res, zero_n], False, bits=1, **tags)
            return Expr.BinaryOp(expr.idx, "And", [ge, nz], False, bits=expr.bits, **tags)

        if target == "__ADD_COND_NBE__":
            # (a + b) >=u a && (a + b) != 0  (x86 unsigned above for ADD)
            a, b = expr.args[0], expr.args[1]
            n = a.bits
            res = Expr.BinaryOp(None, "Add", [a, b], False, bits=n, **tags)
            no_cf = Expr.BinaryOp(None, "CmpGE", [res, a], False, bits=1, **tags)
            zero = Expr.Const(None, None, 0, n, **tags)
            nz = Expr.BinaryOp(None, "CmpNE", [res, zero], False, bits=1, **tags)
            return Expr.BinaryOp(expr.idx, "And", [no_cf, nz], False, bits=expr.bits, **tags)

        if target == "__SBB_COND_A__":
            # zext(a, N+1) >=u (zext(b, N+1) + zext(c, N+1)) && (a - b - c) != 0
            a, b, carry = expr.args[0], expr.args[1], expr.args[2]
            n = a.bits
            ext = n + 1
            a_ext = Expr.Convert(None, n, ext, False, a, **tags)
            b_ext = Expr.Convert(None, n, ext, False, b, **tags)
            c_ext = Expr.Convert(None, n, ext, False, carry, **tags)
            rhs = Expr.BinaryOp(None, "Add", [b_ext, c_ext], False, bits=ext, **tags)
            no_cf = Expr.BinaryOp(None, "CmpGE", [a_ext, rhs], False, bits=1, **tags)
            sub1 = Expr.BinaryOp(None, "Sub", [a, b], False, bits=n, **tags)
            res = Expr.BinaryOp(None, "Sub", [sub1, carry], False, bits=n, **tags)
            zero = Expr.Const(None, None, 0, n, **tags)
            nz = Expr.BinaryOp(None, "CmpNE", [res, zero], False, bits=1, **tags)
            return Expr.BinaryOp(expr.idx, "And", [no_cf, nz], False, bits=expr.bits, **tags)

        if target == "__SBB_COND_L__":
            # sext(a, 2N) <s (sext(b, 2N) + zext(c, 2N))
            a, b, carry = expr.args[0], expr.args[1], expr.args[2]
            n = a.bits
            ext = 2 * n
            a_ext = Expr.Convert(None, n, ext, True, a, **tags)
            b_ext = Expr.Convert(None, n, ext, True, b, **tags)
            c_ext = Expr.Convert(None, n, ext, False, carry, **tags)
            rhs = Expr.BinaryOp(None, "Add", [b_ext, c_ext], False, bits=ext, **tags)
            return Expr.BinaryOp(expr.idx, "CmpLT", [a_ext, rhs], True, bits=expr.bits, **tags)

    # Convert is a subclass of UnaryOp — check it first
    if isinstance(expr, Expr.Convert):
        new_op = _replace_flag_builtins(expr.operand)
        if new_op is not expr.operand:
            return Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_op, **(expr.tags or {}))
        return expr

    if isinstance(expr, Expr.UnaryOp):
        new_op = _replace_flag_builtins(expr.operand)
        if new_op is not expr.operand:
            return Expr.UnaryOp(expr.idx, expr.op, new_op, bits=expr.bits, **(expr.tags or {}))
        return expr

    if isinstance(expr, Expr.BinaryOp):
        new_ops = [_replace_flag_builtins(op) for op in expr.operands]
        if any(n is not o for n, o in zip(new_ops, expr.operands)):
            return Expr.BinaryOp(expr.idx, expr.op, new_ops, expr.signed, bits=expr.bits, **(expr.tags or {}))
        return expr

    if isinstance(expr, Expr.ITE):
        new_cond = _replace_flag_builtins(expr.cond)
        new_true = _replace_flag_builtins(expr.iftrue)
        new_false = _replace_flag_builtins(expr.iffalse)
        if new_cond is not expr.cond or new_true is not expr.iftrue or new_false is not expr.iffalse:
            return Expr.ITE(expr.idx, new_cond, new_true, new_false, **(expr.tags or {}))
        return expr

    return expr


class FlagCondWalker(SequenceWalker):
    """Walk the structured AST replacing flag-condition pseudo-builtins with C expressions."""

    def __init__(self):
        super().__init__(force_forward_scan=True, update_seqnode_in_place=False)
        self.changed = False

    def _handle_Condition(self, node, **kwargs):
        new_true = self._handle(node.true_node, parent=node, index=0) if node.true_node is not None else None
        new_false = self._handle(node.false_node, parent=node, index=1) if node.false_node is not None else None

        new_cond = None
        if node.condition is not None:
            replaced = _replace_flag_builtins(node.condition)
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
            replaced_cond = _replace_flag_builtins(cond) if cond is not None else cond
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


class FlagCondSimplifier(SequenceOptimizationPass):
    """
    Rewrites flag-condition pseudo-builtins (``__DEC_COND_LE__``,
    ``__ADD_COND_LE__``, ``__ADD_COND_HI__``, ``__ADD_COND_GE__``,
    ``__ADD_COND_GT__``, ``__SBB_COND_A__``, ``__SBB_COND_L__``) into
    equivalent C-level comparison expressions.

    This pass runs after structuring, lowering the abstract flag semantics
    that ccall rewriters emit into concrete arithmetic the C backend can print.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Simplify flag condition checks to C expressions"
    DESCRIPTION = "Rewrites flag-condition builtins into C-level comparisons"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _analyze(self, cache=None):
        walker = FlagCondWalker()
        result = walker.walk(self.seq)
        self.out_seq = result if result is not None else self.seq
