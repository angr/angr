from angr.ailment.expression import BinaryOp, Const, UnaryOp

from .base import PeepholeOptimizationExprBase


class BinaryOpCanonicalization(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Canonicalize associative binary operations"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if not self._can_reassociate(expr):
            return None
        if expr.op == "Xor":
            return self._optimize_xor(expr)
        if expr.op in {"Add", "Sub"}:
            if expr.op == "Add":
                r = self._optimize_add_of_disjoint_ands(expr)
                if r is not None:
                    return r
            return self._optimize_add_sub(expr)
        return None

    @staticmethod
    def _can_reassociate(expr: BinaryOp) -> bool:
        return expr.bits is not None and not expr.floating_point and expr.rounding_mode is None

    @staticmethod
    def _has_same_bits(expr, bits: int) -> bool:
        return getattr(expr, "bits", None) == bits

    @staticmethod
    def _const(value: int, expr: BinaryOp) -> Const:
        bits = expr.bits
        if bits is not None:
            value &= (1 << bits) - 1
        return Const(expr.idx, None, value, bits, **expr.tags)

    @staticmethod
    def _append_or_cancel(terms, term) -> bool:
        for idx, existing in enumerate(terms):
            if term.likes(existing):
                del terms[idx]
                return True
        terms.append(term)
        return False

    @staticmethod
    def _build_binary_expr(expr: BinaryOp, op: str, operands):
        if not operands:
            return BinaryOpCanonicalization._const(0, expr)

        new_expr = operands[0]
        for operand in operands[1:]:
            new_expr = BinaryOp(expr.idx, op, [new_expr, operand], expr.signed, bits=expr.bits, **expr.tags)
        return new_expr

    @staticmethod
    def _are_complementary_masks(operand_0, operand_1, bits: int) -> bool:
        if not (
            BinaryOpCanonicalization._has_same_bits(operand_0, bits)
            and BinaryOpCanonicalization._has_same_bits(operand_1, bits)
        ):
            return False

        if isinstance(operand_0, Const) and isinstance(operand_1, Const):
            return ((operand_0.value ^ operand_1.value) & ((1 << bits) - 1)) == (1 << bits) - 1

        if (
            isinstance(operand_0, UnaryOp)
            and operand_0.op == "BitwiseNeg"
            and operand_0.operand.likes(operand_1)
        ):
            return True

        if (
            isinstance(operand_1, UnaryOp)
            and operand_1.op == "BitwiseNeg"
            and operand_1.operand.likes(operand_0)
        ):
            return True

        return False

    @staticmethod
    def _optimize_xor(expr: BinaryOp):
        operands = []
        flattened = False

        def collect(item):
            nonlocal flattened
            if not BinaryOpCanonicalization._has_same_bits(item, expr.bits):
                return False
            if (
                isinstance(item, BinaryOp)
                and item.op == "Xor"
                and item.bits == expr.bits
                and BinaryOpCanonicalization._can_reassociate(item)
            ):
                flattened = True
                return collect(item.operands[0]) and collect(item.operands[1])
            else:
                operands.append(item)
                return True

        if not (collect(expr.operands[0]) and collect(expr.operands[1])):
            return None

        terms = []
        const_value = 0
        const_count = 0
        canceled = False

        for operand in operands:
            if isinstance(operand, Const):
                const_value ^= operand.value
                const_count += 1
            else:
                canceled |= BinaryOpCanonicalization._append_or_cancel(terms, operand)

        if expr.bits is not None:
            const_value &= (1 << expr.bits) - 1

        if const_value != 0:
            terms.append(BinaryOpCanonicalization._const(const_value, expr))

        if not (flattened or canceled or const_count > 1 or (const_count == 1 and const_value == 0)):
            return None

        new_expr = BinaryOpCanonicalization._build_binary_expr(expr, "Xor", terms)
        return None if new_expr.likes(expr) else new_expr

    @staticmethod
    def _optimize_add_of_disjoint_ands(expr: BinaryOp):
        operand_0, operand_1 = expr.operands
        if not (
            isinstance(operand_0, BinaryOp)
            and isinstance(operand_1, BinaryOp)
            and operand_0.op == "And"
            and operand_1.op == "And"
            and operand_0.bits == expr.bits
            and operand_1.bits == expr.bits
            and BinaryOpCanonicalization._can_reassociate(operand_0)
            and BinaryOpCanonicalization._can_reassociate(operand_1)
        ):
            return None

        if any(
            BinaryOpCanonicalization._are_complementary_masks(left_operand, right_operand, expr.bits)
            for left_operand in operand_0.operands
            for right_operand in operand_1.operands
        ):
            return BinaryOp(expr.idx, "Or", [operand_0, operand_1], expr.signed, bits=expr.bits, **expr.tags)

        return None

    @staticmethod
    def _optimize_add_sub(expr: BinaryOp):
        positive = []
        negative = []
        const_sum = 0
        const_count = 0
        canceled = False

        def collect(item, sign):
            nonlocal const_sum, const_count, canceled
            if not BinaryOpCanonicalization._has_same_bits(item, expr.bits):
                return False
            if (
                isinstance(item, BinaryOp)
                and item.op in {"Add", "Sub"}
                and item.bits == expr.bits
                and BinaryOpCanonicalization._can_reassociate(item)
            ):
                return collect(item.operands[0], sign) and collect(
                    item.operands[1], sign if item.op == "Add" else -sign
                )
            elif isinstance(item, Const):
                const_sum += sign * item.value
                const_count += 1
                return True
            elif sign > 0:
                for idx, existing in enumerate(negative):
                    if item.likes(existing):
                        del negative[idx]
                        canceled = True
                        return True
                positive.append(item)
                return True
            else:
                for idx, existing in enumerate(positive):
                    if item.likes(existing):
                        del positive[idx]
                        canceled = True
                        return True
                negative.append(item)
                return True

        if not (
            collect(expr.operands[0], 1)
            and collect(expr.operands[1], 1 if expr.op == "Add" else -1)
        ):
            return None

        if expr.bits is not None:
            mask = (1 << expr.bits) - 1
            const_value = const_sum & mask
            if const_value and const_value > (1 << (expr.bits - 1)):
                const_sign = -1
                const_value = (-const_value) & mask
            else:
                const_sign = 1
        elif const_sum < 0:
            const_sign = -1
            const_value = -const_sum
        else:
            const_sign = 1
            const_value = const_sum

        zero_const = const_count > 0 and const_value == 0
        if not (canceled or const_count > 1 or zero_const):
            return None

        if positive:
            new_expr = BinaryOpCanonicalization._build_binary_expr(expr, "Add", positive)
        else:
            new_expr = BinaryOpCanonicalization._const(0, expr)

        for term in negative:
            new_expr = BinaryOp(expr.idx, "Sub", [new_expr, term], expr.signed, bits=expr.bits, **expr.tags)

        if const_value != 0:
            op = "Add" if const_sign > 0 else "Sub"
            new_expr = BinaryOp(
                expr.idx,
                op,
                [new_expr, BinaryOpCanonicalization._const(const_value, expr)],
                expr.signed,
                bits=expr.bits,
                **expr.tags,
            )

        return None if new_expr.likes(expr) else new_expr
