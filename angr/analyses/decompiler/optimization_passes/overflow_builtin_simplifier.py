# pylint:disable=arguments-renamed
from __future__ import annotations

from angr import ailment
from angr.ailment import Expr, Stmt
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.ailment.tagged_object import TagDict
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import CodeNode, ConditionNode, MultiNode, SequenceNode

from .optimization_pass import OptimizationPassStage, SequenceOptimizationPass


_OF_MAP = {
    "__OFADD__": ("__builtin_add_overflow", ("Add",)),
    "__OFMUL__": ("__builtin_mul_overflow", ("Mul", "Mull")),
}


def _extract_of_call(condition):
    """
    Extract an overflow call from a condition expression.

    Returns ``(call_expr, negated)`` or ``(None, False)``.
    """

    negated = False
    expr = condition
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

    if isinstance(expr, Expr.Call) and isinstance(expr.target, str) and expr.target in _OF_MAP:
        return expr, negated

    return None, False


def _find_blocks(node):
    if isinstance(node, ailment.Block):
        return [node]
    if isinstance(node, CodeNode):
        return _find_blocks(node.node)
    if isinstance(node, (SequenceNode, MultiNode)):
        blocks = []
        for child in node.nodes:
            blocks.extend(_find_blocks(child))
        return blocks
    return []


def _find_binop_in_expr(expr, arith_ops, a, b):
    if isinstance(expr, Expr.BinaryOp) and expr.op in arith_ops:
        operands = expr.operands
        if (operands[0].likes(a) and operands[1].likes(b)) or (operands[0].likes(b) and operands[1].likes(a)):
            return expr
    if isinstance(expr, Expr.Convert):
        return _find_binop_in_expr(expr.operand, arith_ops, a, b)
    return None


def _find_return_with_arithmetic(node, arith_ops, a, b):
    for block in _find_blocks(node):
        for stmt_index, stmt in enumerate(block.statements):
            if isinstance(stmt, Stmt.Return) and stmt.ret_exprs:
                for ret_expr in stmt.ret_exprs:
                    match = _find_binop_in_expr(ret_expr, arith_ops, a, b)
                    if match is not None:
                        return block, stmt_index, match
    return None, None, None


def _replace_expr(expr, old_binop, new_expr):
    if expr is old_binop:
        return new_expr
    if isinstance(expr, Expr.Convert) and expr.operand is old_binop:
        return Expr.Convert(expr.idx, new_expr.bits, expr.to_bits, expr.is_signed, new_expr, **expr.tags)
    return expr


def _collect_vvarids_from_expr(obj, varids):
    if isinstance(obj, VirtualVariable):
        varids.add(obj.varid)
        return
    if hasattr(obj, "operands"):
        for operand in obj.operands:
            _collect_vvarids_from_expr(operand, varids)
    if hasattr(obj, "operand"):
        _collect_vvarids_from_expr(obj.operand, varids)
    if isinstance(obj, Stmt.Return) and obj.ret_exprs:
        for ret_expr in obj.ret_exprs:
            _collect_vvarids_from_expr(ret_expr, varids)
    if isinstance(obj, Expr.Call) and obj.args:
        for arg in obj.args:
            _collect_vvarids_from_expr(arg, varids)
    if hasattr(obj, "condition"):
        cond = getattr(obj, "condition", None)
        if cond is not None and isinstance(cond, Expr.Expression):
            _collect_vvarids_from_expr(cond, varids)


def _collect_vvarids(node):
    varids = set()
    for block in _find_blocks(node):
        for stmt in block.statements:
            _collect_vvarids_from_expr(stmt, varids)
    return varids


class OverflowBuiltinWalker(SequenceWalker):
    """
    Rewrite structured overflow-check patterns to ``__builtin_*_overflow``.
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
        of_call, negated = _extract_of_call(cond_node.condition)
        if of_call is None:
            return False

        target_name = of_call.target
        assert isinstance(target_name, str)
        if target_name not in _OF_MAP:
            return False

        builtin_name, arith_ops = _OF_MAP[target_name]
        if not of_call.args or len(of_call.args) < 2:
            return False

        a, b = of_call.args[0], of_call.args[1]
        arith_block, arith_stmt_idx, arith_binop = self._find_arithmetic(cond_node, next_node, negated, arith_ops, a, b)
        if arith_binop is None:
            return False
        assert arith_block is not None
        assert arith_stmt_idx is not None

        arith_bits = arith_binop.bits
        new_varid = self._next_varid()
        tags: TagDict = of_call.tags or {}
        result_vvar = VirtualVariable(
            self._manager.next_atom(),
            new_varid,
            arith_bits,
            VirtualVariableCategory.UNKNOWN,
            **tags,
        )
        ref_expr = Expr.UnaryOp(
            self._manager.next_atom(),
            "Reference",
            result_vvar,
            bits=arith_bits,
            **tags,
        )
        new_call = Expr.Call(
            of_call.idx,
            builtin_name,
            args=[a, b, ref_expr],
            bits=of_call.bits,
            **tags,
        )
        new_condition = Expr.UnaryOp(None, "Not", new_call, bits=of_call.bits, **tags) if negated else new_call
        cond_node.condition = new_condition

        ret_stmt = arith_block.statements[arith_stmt_idx]
        assert isinstance(ret_stmt, Stmt.Return)
        new_ret_exprs = [_replace_expr(ret_expr, arith_binop, result_vvar) for ret_expr in ret_stmt.ret_exprs]
        arith_block.statements[arith_stmt_idx] = Stmt.Return(ret_stmt.idx, new_ret_exprs, **ret_stmt.tags)

        self.changed = True
        return True

    def _handle_Sequence(self, node, **kwargs):
        changed = False
        new_nodes = list(node.nodes)

        for idx in range(len(new_nodes) - 1):
            cond_node = new_nodes[idx]
            next_node = new_nodes[idx + 1]
            if isinstance(cond_node, ConditionNode) and self._try_rewrite_cond(cond_node, next_node):
                changed = True

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

        result = super()._handle_Sequence(node, **kwargs)
        if result is not None:
            return result
        if changed:
            return node
        return None

    @staticmethod
    def _find_arithmetic(cond_node, next_node, negated, arith_ops, a, b):
        if cond_node.true_node is not None and cond_node.false_node is not None:
            block, idx, binop = _find_return_with_arithmetic(cond_node.true_node, arith_ops, a, b)
            if binop is not None:
                return block, idx, binop
            block, idx, binop = _find_return_with_arithmetic(cond_node.false_node, arith_ops, a, b)
            if binop is not None:
                return block, idx, binop

        if next_node is not None:
            if not negated and cond_node.true_node is not None and cond_node.false_node is None:
                block, idx, binop = _find_return_with_arithmetic(next_node, arith_ops, a, b)
                if binop is not None:
                    return block, idx, binop

            if negated and cond_node.true_node is not None and cond_node.false_node is None:
                block, idx, binop = _find_return_with_arithmetic(cond_node.true_node, arith_ops, a, b)
                if binop is not None:
                    return block, idx, binop

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
    Transform overflow-check patterns using ``__OFADD__``/``__OFMUL__`` into
    ``__builtin_*_overflow`` calls.
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
        self.out_seq = result if result is not None else self.seq
