from typing import TYPE_CHECKING

from ailment.expression import UnaryOp, BinaryOp, StackBaseOffset, Const

from .base import PeepholeOptimizationExprBase

if TYPE_CHECKING:
    from ailment.expression import Expression


class TidyStackAddr(PeepholeOptimizationExprBase):
    """
    Consolidate StackBaseOffset objects and constant offsets within each stack address expression.
    """

    __slots__ = ()

    NAME = "Tidy stack addresses"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in ("Add", "Sub"):
            return None

        has_binop = any(isinstance(operand, BinaryOp) for operand in expr.operands)
        if not has_binop:
            return None
        # fast path: StackBaseOffset +/- N stays untouched
        if isinstance(expr.operands[0], StackBaseOffset) and isinstance(expr.operands[1], Const):
            return None

        # consolidate all expressions into a list of expressions with their signs (True for +, False for -)
        all_operands: list[tuple[bool, "Expression"]] = []
        stack: list[tuple[bool, "Expression"]] = [(True, expr)]
        stackbase_count = 0
        while stack:
            sign, item = stack.pop(0)
            if isinstance(item, BinaryOp):
                if item.op == "Add":
                    stack.insert(0, (sign, item.operands[0]))
                    stack.insert(0, (sign, item.operands[1]))
                    continue
                if item.op == "Sub":
                    stack.insert(0, (sign, item.operands[0]))
                    stack.insert(0, (not sign, item.operands[1]))
                    continue
            if isinstance(item, StackBaseOffset):
                stackbase_count += 1
            all_operands.insert(0, (sign, item))

        if stackbase_count == 0:
            # only handles stack addresses for now
            return None

        # collect all constants until the next StackBaseOffset object and merge them into the prior StackBaseOffset
        # object.
        stackbaseoffset_objs: list[tuple[bool, StackBaseOffset]] = []

        # find StackBaseOffset objects and record their indices
        stackbaseoffset_indices = []
        for idx, (_, obj) in enumerate(all_operands):
            if isinstance(obj, StackBaseOffset):
                stackbaseoffset_indices.append(idx)

        has_changes = False
        # collect constants
        for i, stackbaseoffset_index in enumerate(stackbaseoffset_indices):
            stackbaseoffset_const = 0
            stackbaseoffset_obj: StackBaseOffset = all_operands[stackbaseoffset_index][1].copy()
            stackbaseoffset_sign: bool = all_operands[stackbaseoffset_index][0]

            next_stackbaseoffset_index = (
                stackbaseoffset_indices[i + 1] if i < len(stackbaseoffset_indices) - 1 else len(all_operands)
            )
            for j in range(i + 1, next_stackbaseoffset_index):
                positive, obj = all_operands[j]
                if isinstance(obj, Const):
                    has_changes = True
                    if positive:
                        stackbaseoffset_const += obj.value
                    else:
                        stackbaseoffset_const -= obj.value
            if stackbaseoffset_const != 0:
                if stackbaseoffset_sign:
                    stackbaseoffset_obj.offset += stackbaseoffset_const
                else:
                    stackbaseoffset_obj.offset += -stackbaseoffset_const
            stackbaseoffset_objs.append((stackbaseoffset_sign, stackbaseoffset_obj))

        if not has_changes:
            return None

        # building the final expression
        expr = None
        while stackbaseoffset_objs:
            sign, obj = stackbaseoffset_objs.pop(0)
            if expr is None:
                if sign:
                    expr = obj
                else:
                    expr = UnaryOp(None, "Neg", obj, **obj.tags)
            else:
                op = "Add" if sign else "Sub"
                expr = BinaryOp(
                    None,
                    op,
                    [
                        expr,
                        obj,
                    ],
                    False,
                    **obj.tags,
                )

        for positive, obj in all_operands:
            if isinstance(obj, (StackBaseOffset, Const)):
                continue
            if expr is None:
                expr = obj
            else:
                op = "Add" if positive else "Sub"
                expr = BinaryOp(
                    None,
                    op,
                    [
                        expr,
                        obj,
                    ],
                    False,
                    **obj.tags,
                )

        return expr
