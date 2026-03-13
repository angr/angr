# pylint:disable=arguments-renamed
from __future__ import annotations

from angr import ailment
from angr.ailment import Expr, Stmt
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.ailment.tagged_object import TagDict

from angr.analyses.decompiler.structuring.structurer_nodes import (
    ConditionNode,
    CodeNode,
    SequenceNode,
    MultiNode,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from .optimization_pass import SequenceOptimizationPass, OptimizationPassStage


# Maps __OFADD__/__OFMUL__ to (builtin_name, arithmetic_ops)
# arithmetic_ops is a tuple of BinaryOp.op values that match the corresponding arithmetic.
# __OFMUL__ can produce either "Mul" (signed) or "Mull" (widening unsigned multiply).
_OF_MAP = {
    "__OFADD__": ("__builtin_add_overflow", ("Add",)),
    "__OFMUL__": ("__builtin_mul_overflow", ("Mul", "Mull")),
}


def _extract_of_call(condition):
    """
    Extract an overflow call from a condition expression.

    Returns (call_expr, negated) or (None, False).
    Unwraps arbitrary nesting of Not and Convert wrappers, e.g.:
      !((char)!(__OFADD__(a, b)))  →  (__OFADD__ call, negated=False)
      !((char)__OFMUL__(a, b))    →  (__OFMUL__ call, negated=True)
      (char)__OFADD__(a, b)       →  (__OFADD__ call, negated=False)
    """
    negated = False
    expr = condition

    # Peel off layers of Not and Convert until we hit something else
    changed = True
    while changed:
        changed = False
        if isinstance(expr, Expr.UnaryOp) and expr.op == "Not":
            negated = not negated
            expr = expr.operand
            changed = True
        if isinstance(expr, Expr.Convert):
            expr = expr.operand
            changed = True

    # Check for __OFADD__ / __OFMUL__ call
    if isinstance(expr, Expr.Call) and isinstance(expr.target, str) and expr.target in _OF_MAP:
        return expr, negated

    return None, False


def _find_blocks(node):
    """Flatten a structured node into a list of AIL blocks."""
    if isinstance(node, ailment.Block):
        return [node]
    if isinstance(node, CodeNode):
        return _find_blocks(node.node)
    if isinstance(node, (SequenceNode, MultiNode)):
        blocks = []
        for n in node.nodes:
            blocks.extend(_find_blocks(n))
        return blocks
    return []


def _find_return_with_arithmetic(node, arith_ops, a, b):
    """
    Search a structured node for a Return statement containing BinaryOp(op, [x, y])
    where op is in arith_ops and x.likes(a) and y.likes(b) (or swapped).

    Returns (block, stmt_index, binary_op) or (None, None, None).
    """
    blocks = _find_blocks(node)
    for block in blocks:
        for i, stmt in enumerate(block.statements):
            if isinstance(stmt, Stmt.Return) and stmt.ret_exprs:
                for ret_expr in stmt.ret_exprs:
                    match = _find_binop_in_expr(ret_expr, arith_ops, a, b)
                    if match is not None:
                        return block, i, match
    return None, None, None


def _find_binop_in_expr(expr, arith_ops, a, b):
    """
    Recursively search an expression for BinaryOp(op, [x, y]) where op is in arith_ops
    and operands match (a, b) or (b, a).
    Returns the BinaryOp if found, else None.
    """
    if isinstance(expr, Expr.BinaryOp) and expr.op in arith_ops:
        ops = expr.operands
        if (ops[0].likes(a) and ops[1].likes(b)) or (ops[0].likes(b) and ops[1].likes(a)):
            return expr
    # Recurse into Convert
    if isinstance(expr, Expr.Convert):
        return _find_binop_in_expr(expr.operand, arith_ops, a, b)
    return None


def _replace_expr(expr, old_binop, new_expr):
    """
    Replace old_binop with new_expr inside an expression tree. Returns the new expression.
    """
    if expr is old_binop:
        return new_expr
    if isinstance(expr, Expr.Convert) and expr.operand is old_binop:
        # The Convert was wrapping the arithmetic — replace inner, keep Convert
        return Expr.Convert(expr.idx, new_expr.bits, expr.to_bits, expr.is_signed, new_expr, **expr.tags)
    return expr


def _collect_vvarids(node):
    """Collect all VirtualVariable varid values from a structured node."""
    varids = set()
    blocks = _find_blocks(node)
    for block in blocks:
        for stmt in block.statements:
            _collect_vvarids_from_expr(stmt, varids)
    return varids


def _collect_vvarids_from_expr(obj, varids):
    """Recursively collect varids from an AIL object."""
    if isinstance(obj, VirtualVariable):
        varids.add(obj.varid)
        return
    # Walk common expression containers
    if hasattr(obj, "operands"):
        for op in obj.operands:
            _collect_vvarids_from_expr(op, varids)
    if hasattr(obj, "operand"):
        _collect_vvarids_from_expr(obj.operand, varids)
    if isinstance(obj, Stmt.Return) and obj.ret_exprs:
        for e in obj.ret_exprs:
            _collect_vvarids_from_expr(e, varids)
    if isinstance(obj, Expr.Call) and obj.args:
        for arg in obj.args:
            _collect_vvarids_from_expr(arg, varids)
    if hasattr(obj, "condition"):
        cond = getattr(obj, "condition", None)
        if cond is not None and isinstance(cond, Expr.Expression):
            _collect_vvarids_from_expr(cond, varids)


class OverflowBuiltinWalker(SequenceWalker):
    """
    Walks a SequenceNode looking for patterns like:

        if (__OFADD__(a, b)) { return ERR; }
        return a + b;

    and transforms them into:

        if (__builtin_add_overflow(a, b, &result)) { return ERR; }
        return result;
    """

    def __init__(self, manager, seq_node):
        super().__init__(force_forward_scan=True, update_seqnode_in_place=False)
        self._manager = manager
        self._seq_node = seq_node
        self._max_varid = None
        self.changed = False

    def _next_varid(self):
        if self._max_varid is None:
            varids = _collect_vvarids(self._seq_node)
            self._max_varid = max(varids) if varids else 0
        self._max_varid += 1
        return self._max_varid

    def _try_rewrite_cond(self, cond_node, next_node):
        """
        Try to rewrite a ConditionNode containing an overflow call into __builtin_*_overflow.
        next_node may be None (for standalone ConditionNodes with both branches).
        Returns True if a rewrite was performed.
        """
        of_call, negated = _extract_of_call(cond_node.condition)
        if of_call is None:
            return False

        target_name = of_call.target
        assert isinstance(target_name, str)
        if target_name not in _OF_MAP:
            return False

        builtin_name, arith_ops = _OF_MAP[target_name]
        call_args = of_call.args
        if not call_args or len(call_args) < 2:
            return False

        a, b = call_args[0], call_args[1]

        # Try to find the matching arithmetic expression
        arith_block, arith_stmt_idx, arith_binop = self._find_arithmetic(cond_node, next_node, negated, arith_ops, a, b)

        if arith_binop is None:
            return False
        assert arith_block is not None
        assert arith_stmt_idx is not None

        # Found a match! Build the replacement.
        arith_bits = arith_binop.bits
        ptr_bits = arith_bits  # pointer size matches data size for this context

        # Create result variable
        new_varid = self._next_varid()
        tags: TagDict = of_call.tags or {}
        result_vvar = VirtualVariable(
            self._manager.next_atom(),
            new_varid,
            arith_bits,
            VirtualVariableCategory.UNKNOWN,
            **tags,
        )

        # Build &result reference expression
        ref_expr = Expr.UnaryOp(
            self._manager.next_atom(),
            "Reference",
            result_vvar,
            bits=ptr_bits,
            **tags,
        )

        # Build new call: __builtin_add_overflow(a, b, &result)
        new_call = Expr.Call(
            of_call.idx,
            builtin_name,
            args=[a, b, ref_expr],
            bits=of_call.bits,
            **tags,
        )

        # Build new condition (with negation if needed)
        new_condition = Expr.UnaryOp(None, "Not", new_call, bits=of_call.bits, **tags) if negated else new_call

        # Apply: update condition
        cond_node.condition = new_condition

        # Apply: replace arithmetic with result_vvar in the return statement
        ret_stmt = arith_block.statements[arith_stmt_idx]
        assert isinstance(ret_stmt, Stmt.Return)
        new_ret_exprs = []
        for ret_expr in ret_stmt.ret_exprs:
            new_ret_exprs.append(_replace_expr(ret_expr, arith_binop, result_vvar))
        arith_block.statements[arith_stmt_idx] = Stmt.Return(ret_stmt.idx, new_ret_exprs, **ret_stmt.tags)

        self.changed = True
        return True

    def _handle_Sequence(self, node, **kwargs):
        changed = False
        new_nodes = list(node.nodes)

        # Pass 1: Try pairs (nodes[i], nodes[i+1]) for Patterns A/B
        i = 0
        while i < len(new_nodes) - 1:
            cond_node = new_nodes[i]
            next_node = new_nodes[i + 1]

            if isinstance(cond_node, ConditionNode) and self._try_rewrite_cond(cond_node, next_node):
                changed = True

            i += 1

        # Pass 2: Try standalone ConditionNodes for Pattern C (if-then-else)
        for child in new_nodes:
            if (
                isinstance(child, ConditionNode)
                and child.true_node is not None
                and child.false_node is not None
                and self._try_rewrite_cond(child, None)
            ):
                changed = True

        if changed:
            node = SequenceNode(node.addr, nodes=new_nodes)

        # Recurse into children
        result = super()._handle_Sequence(node, **kwargs)
        if result is not None:
            return result
        if changed:
            return node
        return None

    @staticmethod
    def _find_arithmetic(cond_node, next_node, negated, arith_ops, a, b):
        """
        Try to locate the matching arithmetic expression in the appropriate branch.

        Returns (block, stmt_idx, binop) or (None, None, None).
        """
        # Pattern C: if-then-else — one branch has arithmetic, the other has error
        if cond_node.true_node is not None and cond_node.false_node is not None:
            # Try true_node for arithmetic
            block, idx, binop = _find_return_with_arithmetic(cond_node.true_node, arith_ops, a, b)
            if binop is not None:
                return block, idx, binop
            # Try false_node for arithmetic
            block, idx, binop = _find_return_with_arithmetic(cond_node.false_node, arith_ops, a, b)
            if binop is not None:
                return block, idx, binop

        if next_node is not None:
            # Pattern A: CondO (not negated) — arithmetic in next_node (fallthrough)
            if not negated and cond_node.true_node is not None and cond_node.false_node is None:
                block, idx, binop = _find_return_with_arithmetic(next_node, arith_ops, a, b)
                if binop is not None:
                    return block, idx, binop

            # Pattern B: CondNO (negated) — arithmetic in true_node
            if negated and cond_node.true_node is not None and cond_node.false_node is None:
                block, idx, binop = _find_return_with_arithmetic(cond_node.true_node, arith_ops, a, b)
                if binop is not None:
                    return block, idx, binop

            # Fallback: try both branches and next_node regardless of negation
            if cond_node.true_node is not None:
                block, idx, binop = _find_return_with_arithmetic(cond_node.true_node, arith_ops, a, b)
                if binop is not None:
                    return block, idx, binop

            block, idx, binop = _find_return_with_arithmetic(next_node, arith_ops, a, b)
            if binop is not None:
                return block, idx, binop

        return None, None, None


class OverflowBuiltinSimplifier(SequenceOptimizationPass):
    """
    Transforms overflow-check patterns using __OFADD__/__OFMUL__ into
    __builtin_add_overflow/__builtin_mul_overflow calls.

    Before:
        if (__OFADD__(a, b)) { return ERR; }
        return a + b;

    After:
        if (__builtin_add_overflow(a, b, &result)) { return ERR; }
        return result;

    .. note::
        Disabling this pass will leave IDA-style ``__OFADD__``/``__OFMUL__``
        macros in the decompiled output whenever paired arithmetic is present.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Simplify overflow checks to __builtin_*_overflow"
    DESCRIPTION = "Rewrites __OFADD__/__OFMUL__ + arithmetic patterns into __builtin_*_overflow builtins"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return bool(self.seq is not None and self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = OverflowBuiltinWalker(self.manager, self.seq)
        result = walker.walk(self.seq)
        if result is not None:
            self.out_seq = result
        else:
            self.out_seq = self.seq
