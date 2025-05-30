# pylint:disable=line-too-long
from __future__ import annotations
import logging
import math

from angr.ailment import Expr
from unique_log_filter import UniqueLogFilter

from .engine_base import SimplifierAILEngine, SimplifierAILState
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)
_l.addFilter(UniqueLogFilter())


class DivSimplifierAILEngine(SimplifierAILEngine):
    """
    An AIL pass for the div simplifier
    """

    @staticmethod
    def _check_divisor(a: int, b: int, ndigits: int = 6) -> int | None:
        if b == 0:
            return None
        divisor_1 = 1 + (a // b)
        divisor_2 = int(round(a / float(b), ndigits))
        return divisor_1 if divisor_1 == divisor_2 else None

    # pylint: disable=too-many-boolean-expressions
    def _handle_expr_Convert(self, expr: Expr.Convert):
        if expr.from_bits == 128 and expr.to_bits == 64:
            operand_expr = self._expr(expr.operand)
            if (
                (
                    isinstance(operand_expr, Expr.BinaryOp)
                    and operand_expr.op == "Mul"
                    and isinstance(operand_expr.operands[1], Expr.Const)
                    and isinstance(operand_expr.operands[0], Expr.BinaryOp)
                )
                and operand_expr.operands[0].op in {"Shr", "Mod"}
                and isinstance(operand_expr.operands[0].operands[1], Expr.Const)
            ):
                if operand_expr.operands[0].op == "Shr":
                    Y = operand_expr.operands[0].operands[1].value
                    assert isinstance(Y, int)
                else:
                    Y = int(math.log2(operand_expr.operands[0].operands[1].value))
                C = operand_expr.operands[1].value
                assert isinstance(C, int)
                divisor = self._check_divisor(pow(2, 64 + Y), C)
                if divisor:
                    X = operand_expr.operands[0].operands[0]
                    new_const = Expr.Const(expr.idx, None, divisor, 64)
                    return Expr.BinaryOp(expr.idx, "Div", [X, new_const], expr.signed, **expr.tags)

        return expr

    def _handle_binop_Shr(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        X = None
        divisor = None

        if (
            isinstance(operand_1, Expr.Const)
            and isinstance(operand_0, Expr.BinaryOp)
            and operand_0.op == "Mod"
            and isinstance(operand_0.operands[1], Expr.Const)
        ):
            divisor = operand_0.operands[1].value * pow(2, operand_1.value)
            X = operand_0.operands[0]
        if (
            isinstance(operand_1, Expr.Const)
            and isinstance(operand_0, Expr.Convert)
            and isinstance(operand_0.operand, Expr.BinaryOp)
            and operand_0.operand.op == "Mod"
            and isinstance(operand_0.operand.operands[1], Expr.Const)
        ):
            divisor = operand_0.operand.operands[1].value * pow(2, operand_1.value)
            X = operand_0.operand.operands[0]
        if (
            (
                isinstance(operand_1, Expr.Const)
                and isinstance(operand_0, Expr.Convert)
                and operand_0.from_bits == 128
                and operand_0.to_bits == 64
            )
            and isinstance(operand_0.operand, Expr.BinaryOp)
            and operand_0.operand.op == "Mul"
        ):
            if isinstance(operand_0.operand.operands[1], Expr.Const):
                C = operand_0.operand.operands[1].value
                Y = operand_1.value
                assert isinstance(C, int)
                assert isinstance(Y, int)
                divisor = self._check_divisor(pow(2, 64 + Y), C)
                X = operand_0.operand.operands[0]
            elif isinstance(operand_0.operand.operands[0], Expr.BinaryOp) and operand_0.operand.operands[0].op in {
                "Shr",
                "Mod",
            }:
                C = operand_0.operand.operands[1].value
                Z = operand_1.value
                if operand_0.operand.operands[0].op == "Shr":
                    Y = operand_0.operand.operands[0].operands[1].value
                else:
                    Y = int(math.log2(operand_0.operand.operands[0].operands[1].value))
                assert isinstance(C, int)
                assert isinstance(Y, int)
                assert isinstance(Z, int)
                divisor = self._check_divisor(pow(2, 64 + Z + Y), C)
                X = operand_0.operand.operands[0].operands[0]
        if isinstance(operand_1, Expr.Const) and isinstance(operand_0, Expr.BinaryOp) and operand_0.op == "Add":
            add_0, add_1 = operand_0.operands
            Z = operand_1.value
            if add_0.has_atom(add_1) or add_1.has_atom(add_0):
                xC = add_1 if add_0.has_atom(add_1) else add_0
                x_xC = add_0 if add_0.has_atom(add_1) else add_1
                if isinstance(xC, Expr.Convert) and (xC.from_bits > xC.to_bits):
                    Y = xC.from_bits - xC.to_bits
                    if isinstance(xC.operand, Expr.BinaryOp) and xC.operand.op == "Mul":
                        xC_ = xC.operand
                        if isinstance(xC_.operands[1], Expr.Const):
                            C = xC_.operands[1].value
                            X = xC_.operands[0]
                            if isinstance(x_xC, Expr.BinaryOp) and x_xC.op == "Shr":
                                V_, V = x_xC.operands
                                if isinstance(V, Expr.Const):
                                    V = V.value
                                    if (
                                        isinstance(V_, Expr.BinaryOp)
                                        and V_.op == "Sub"
                                        and V_.operands[0] == X
                                        and V_.operands[1] == xC
                                    ):
                                        assert isinstance(Y, int)
                                        assert isinstance(Z, int)
                                        assert isinstance(V, int)
                                        divisor = self._check_divisor(
                                            pow(2, Y + V + Z), C * (pow(2, V) - 1) + pow(2, Y)
                                        )
                # unsigned int here
                if isinstance(xC, Expr.BinaryOp) and xC.op == "Mul":
                    if isinstance(xC.operands[1], Expr.Const) and isinstance(xC.operands[0], Expr.Convert):
                        C = xC.operands[1].value
                        X = xC.operands[0]
                        Y = X.from_bits - X.to_bits
                        if isinstance(x_xC, Expr.BinaryOp) and x_xC.op == "Shr":
                            V_, V = x_xC.operands
                            if isinstance(V, Expr.Const):
                                V = V.value
                                if isinstance(V_, Expr.BinaryOp) and V_.op == "Sub" and V_.operands[1] == xC:
                                    assert isinstance(Y, int)
                                    assert isinstance(Z, int)
                                    assert isinstance(V, int)
                                    divisor = self._check_divisor(pow(2, Y + V + Z), C * (pow(2, V) - 1) + pow(2, Y))
                elif (
                    isinstance(xC, Expr.BinaryOp)
                    and xC.op == "Shr"
                    and (
                        isinstance(xC.operands[1], Expr.Const)
                        and isinstance(xC.operands[0], Expr.BinaryOp)
                        and xC.operands[0].op == "Mul"
                        and isinstance(xC.operands[0].operands[1], Expr.Const)
                    )
                    and (
                        isinstance(x_xC, Expr.BinaryOp)
                        and isinstance(x_xC.operands[1], Expr.Const)
                        and isinstance(x_xC.operands[0], Expr.BinaryOp)
                        and x_xC.op == "Shr"
                        and x_xC.operands[0].op == "Sub"
                    )
                ):
                    X = xC.operands[0].operands[0]
                    C = xC.operands[0].operands[1].value
                    Y = xC.operands[1].value
                    V = x_xC.operands[1].value
                    if x_xC.operands[0].operands[0] == X:
                        assert isinstance(Y, int)
                        assert isinstance(Z, int)
                        assert isinstance(V, int)
                        divisor = self._check_divisor(pow(2, Y + V + Z), C * (pow(2, V) - 1) + pow(2, Y))

        # unsigned int
        if (
            isinstance(operand_1, Expr.Const)
            and isinstance(operand_0, Expr.BinaryOp)
            and operand_0.op == "Mul"
            and isinstance(operand_0.operands[1], Expr.Const)
        ):
            if isinstance(operand_0.operands[0], Expr.Convert):
                V = operand_0.operands[0].from_bits - operand_0.operands[0].to_bits
                C = operand_0.operands[1].value
                Z = operand_1.value
                X = operand_0.operands[0]
                assert isinstance(C, int)
                assert isinstance(Z, int)
                assert isinstance(V, int)
                divisor = self._check_divisor(pow(2, V + Z), C)
            elif (
                isinstance(operand_0.operands[0], Expr.BinaryOp)
                and isinstance(operand_0.operands[0].operands[1], Expr.Const)
                and operand_0.operands[0].op in {"Shr", "Mod"}
            ):
                X = operand_0.operands[0].operands[0]
                V = 0
                ndigits = 6
                if isinstance(X, Expr.Convert):
                    V = X.from_bits - X.to_bits
                if V == 32:
                    ndigits = 5
                C = operand_0.operands[1].value
                Y = operand_0.operands[0].operands[1].value
                if operand_0.operands[0].op == "Mod":
                    Y = int(math.log2(operand_0.operands[0].operands[1].value))
                Z = operand_1.value
                assert isinstance(Y, int)
                assert isinstance(Z, int)
                assert isinstance(V, int)
                assert isinstance(C, int)
                divisor = self._check_divisor(pow(2, Y + Z + V), C, ndigits)
            else:
                X = operand_0.operands[0]
                Y = operand_1.value
                C = operand_0.operands[1].value
                assert isinstance(Y, int)
                assert isinstance(C, int)
                divisor = self._check_divisor(pow(2, Y), C)

        if divisor and X:
            new_const = Expr.Const(expr.idx, None, divisor, 64)
            return Expr.BinaryOp(expr.idx, "Div", [X, new_const], expr.signed, **expr.tags)

        if isinstance(operand_1, Expr.Const):
            if isinstance(operand_0, Expr.VirtualVariable) and operand_0.was_reg:
                new_operand = Expr.Const(operand_1.idx, None, 2**operand_1.value, operand_0.bits)
                return Expr.BinaryOp(expr.idx, "Div", [operand_0, new_operand], expr.signed)
            if (
                isinstance(operand_0, Expr.BinaryOp)
                and operand_0.op == "Shr"
                and isinstance(operand_0.operands[1], Expr.Const)
            ):
                new_const = Expr.Const(
                    operand_1.idx, None, operand_0.operands[1].value + operand_1.value, operand_1.bits
                )
                return Expr.BinaryOp(expr.idx, "Shr", [operand_0.operands[0], new_const], expr.signed, **expr.tags)

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, "Shr", [operand_0, operand_1], expr.signed)
        return expr

    def _handle_binop_Mul(self, expr):
        operand_0, operand_1 = expr.operands

        if (
            isinstance(operand_1, Expr.Const)
            and isinstance(operand_0, Expr.BinaryOp)
            and isinstance(operand_0.operands[1], Expr.Const)
            and operand_0.op in {"Mod", "Shr"}
        ):
            assert isinstance(operand_0.operands[1].value, int)
            assert isinstance(operand_1.value, int)
            Y = int(math.log2(operand_0.operands[1].value)) if operand_0.op == "Mod" else operand_0.operands[1].value
            C = operand_1.value
            X = operand_0.operands[0]
            # there is a convert outside this expr
            V = 64
            if isinstance(X, Expr.Convert):
                V = X.from_bits - X.to_bits
            ndigits = 5 if V == 32 else 6
            if (divisor := self._check_divisor(pow(2, V + Y), C, ndigits)) and X:
                new_const = Expr.Const(expr.idx, None, divisor, 64)
                return Expr.BinaryOp(expr.idx, "Div", [X, new_const], expr.signed, **expr.tags)
        if (
            isinstance(operand_1, Expr.Const)
            and isinstance(operand_0, Expr.Convert)
            and isinstance(operand_0.operand, Expr.BinaryOp)
            and isinstance(operand_0.operand.operands[1], Expr.Const)
            and operand_0.operand.op in {"Mod", "Shr"}
            and isinstance(operand_1.value, int)
        ):
            assert isinstance(operand_0.operand.operands[1].value, int)
            if operand_0.operand.op == "Mod":
                Y = int(math.log2(operand_0.operand.operands[1].value))
            else:
                Y = operand_0.operand.operands[1].value
            C = operand_1.value
            X = operand_0.operand.operands[0]
            V = operand_0.from_bits - operand_0.to_bits
            ndigits = 5 if V == 32 else 6
            if (divisor := self._check_divisor(pow(2, V + Y), C, ndigits)) and X:
                new_const = Expr.Const(expr.idx, None, divisor, 64)
                return Expr.BinaryOp(expr.idx, "Div", [X, new_const], expr.signed, **expr.tags)
        return expr

    def _handle_binop_Div(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if (
            isinstance(operand_1, Expr.Const)
            and isinstance(operand_0, Expr.BinaryOp)
            and operand_0.op in {"Div", "Mod"}
            and isinstance(operand_0.operands[1], Expr.Const)
        ):
            new_const_value = operand_1.value * operand_0.operands[1].value
            new_const = Expr.Const(operand_1.idx, None, new_const_value, operand_1.bits)
            return Expr.BinaryOp(expr.idx, "Div", [operand_0.operands[0], new_const], expr.signed, **expr.tags)

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, "Div", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr

    def _handle_binop_Add(self, expr):
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        matched, new_expr = self._match_signed_division_add_operands(op0, op1)
        if matched:
            return new_expr
        matched, new_expr = self._match_signed_division_add_operands(op1, op0)  # pylint:disable=arguments-out-of-order
        if matched:
            return new_expr

        return expr

    def _match_signed_division_add_operands(self, op0, op1):
        # From: Add((Conv(64->32, ((Load(addr=stack_base+4, size=4, endness=Iend_LE) Mulls 0x55555556<32>)
        #            >> 0x20<8>)) >> 0x1f<8>),
        #            Conv(64->32, ((Load(addr=stack_base+4, size=4, endness=Iend_LE) Mulls 0x55555556<32>) >> 0x20<8>)))
        # To: Load(addr=stack_base+4, size=4, endness=Iend_LE) /s 3

        # op0
        if not (
            isinstance(op0, Expr.BinaryOp)
            and op0.op == "Shr"
            and isinstance(op0.operands[1], Expr.Const)
            and op0.operands[1].value == 0x1F
        ):
            return False, None
        if not (
            isinstance(op0.operands[0], Expr.Convert)
            and op0.operands[0].from_bits == 64
            and op0.operands[0].to_bits == 32
        ):
            return False, None

        op0_inner = op0.operands[0].operand
        if not (
            isinstance(op0_inner, Expr.BinaryOp)
            and op0_inner.op == "Shr"
            and isinstance(op0_inner.operands[1], Expr.Const)
            and op0_inner.operands[1].value == 32
        ):
            return False, None

        # op1
        if op1 != op0.operands[0]:
            return False, None

        # extract
        inner = op0_inner.operands[0]
        if isinstance(inner, Expr.BinaryOp) and inner.op == "Mull" and inner.signed:
            operand_0, operand_1 = inner.operands

            if isinstance(operand_1, Expr.Const) and not isinstance(operand_0, Expr.Const):
                # swap them
                operand_0, operand_1 = operand_1, operand_0

            if isinstance(operand_0, Expr.Const) and not isinstance(operand_1, Expr.Const) and operand_0.bits == 32:
                bits = operand_0.bits
                C = operand_0.value
                X = operand_1
                V = bits
                ndigits = 5 if V == 32 else 6
                assert isinstance(C, int)
                divisor = self._check_divisor(pow(2, V), C, ndigits)
                if divisor is not None and X:
                    new_const = Expr.Const(None, None, divisor, V)
                    new_expr = Expr.BinaryOp(inner.idx, "Div", [X, new_const], inner.signed, **inner.tags)
                    return True, new_expr

        return False, None


class DivSimplifier(OptimizationPass):
    """
    Simplifies various division optimizations back to "div".
    """

    ARCHES = [
        "X86",
        "AMD64",
        "ARMCortexM",
        "ARMHF",
        "ARMEL",
    ]
    PLATFORMS = None  # everything
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify arithmetic division"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.engine = DivSimplifierAILEngine(self.project)

        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            new_block = block
            old_block = None

            while new_block != old_block:
                old_block = new_block
                new_block = self.engine.process(state=self.state.copy(), block=old_block.copy())
                _l.debug("new block: %s", new_block.statements)

            self._update_block(block, new_block)
