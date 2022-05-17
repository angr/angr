import logging
import math

from ailment import Expr

from .engine_base import SimplifierAILEngine, SimplifierAILState
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class DivSimplifierAILEngine(SimplifierAILEngine):
    """
    An AIL pass for the div simplifier
    """

    def _check_divisor(self, a, b, ndigits=6): #pylint: disable=no-self-use
        divisor_1 = 1 + (a//b)
        divisor_2 = int(round(a/float(b), ndigits))
        return divisor_1 if divisor_1 == divisor_2 else None

    # pylint: disable=too-many-boolean-expressions
    def _ail_handle_Convert(self, expr):
        if expr.from_bits == 128 and expr.to_bits == 64:
            operand_expr = self._expr(expr.operand)
            if isinstance(operand_expr, Expr.BinaryOp) \
                    and operand_expr.op == 'Mul' \
                    and isinstance(operand_expr.operands[1], Expr.Const) \
                    and isinstance(operand_expr.operands[0], Expr.BinaryOp):
                if operand_expr.operands[0].op in {'Shr', 'DivMod'} \
                        and isinstance(operand_expr.operands[0].operands[1], Expr.Const):
                    if operand_expr.operands[0].op == 'Shr':
                        Y = operand_expr.operands[0].operands[1].value
                    else:
                        Y = int(math.log2(operand_expr.operands[0].operands[1].value))
                    C = operand_expr.operands[1].value
                    divisor = self._check_divisor(pow(2, 64+Y), C)
                    if divisor:
                        X = operand_expr.operands[0].operands[0]
                        new_const = Expr.Const(expr.idx, None, divisor, 64)
                        return Expr.BinaryOp(expr.idx, 'DivMod', [X, new_const], expr.signed, **expr.tags)

        if expr.from_bits == 64 and expr.to_bits == 32 \
                and isinstance(expr.operand, Expr.BinaryOp) and expr.operand.op == "Shr" \
                and isinstance(expr.operand.operands[1], Expr.Const) and expr.operand.operands[1].value == expr.to_bits:
            inner = expr.operand.operands[0]
            if isinstance(inner, Expr.BinaryOp) and inner.op == "Mull":
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
                    divisor = self._check_divisor(pow(2, V), C, ndigits)
                    if divisor is not None and X:
                        new_const = Expr.Const(None, None, divisor, V)
                        new_expr = Expr.BinaryOp(inner.idx, 'Div', [X, new_const], inner.signed, **inner.tags)
                        return new_expr

        return super()._ail_handle_Convert(expr)

    def _ail_handle_Shr(self, expr):

        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        X = None
        divisor = None

        if isinstance(operand_1, Expr.Const) \
            and isinstance(operand_0, Expr.BinaryOp) \
                and operand_0.op == 'DivMod' \
                    and isinstance(operand_0.operands[1], Expr.Const):
            divisor = operand_0.operands[1].value * pow(2, operand_1.value)
            X = operand_0.operands[0]
        if isinstance(operand_1, Expr.Const) \
            and isinstance(operand_0, Expr.Convert) \
                and isinstance(operand_0.operand, Expr.BinaryOp) \
                    and operand_0.operand.op == 'DivMod' \
                and isinstance(operand_0.operand.operands[1], Expr.Const):
            divisor = operand_0.operand.operands[1].value * pow(2, operand_1.value)
            X = operand_0.operand.operands[0]
        if isinstance(operand_1, Expr.Const) \
                and isinstance(operand_0, Expr.Convert) \
                and operand_0.from_bits == 128 \
                and operand_0.to_bits == 64:
            if isinstance(operand_0.operand, Expr.BinaryOp)\
                    and operand_0.operand.op == 'Mul':
                if isinstance(operand_0.operand.operands[1], Expr.Const):
                    C = operand_0.operand.operands[1].value
                    Y = operand_1.value
                    divisor = self._check_divisor(pow(2, 64+Y), C)
                    X = operand_0.operand.operands[0]
                elif isinstance(operand_0.operand.operands[0], Expr.BinaryOp) \
                        and operand_0.operand.operands[0].op in {'Shr', 'DivMod'}:
                    C = operand_0.operand.operands[1].value
                    Z = operand_1.value
                    if operand_0.operand.operands[0].op == 'Shr':
                        Y = operand_0.operand.operands[0].operands[1].value
                    else:
                        Y = int(math.log2(operand_0.operand.operands[0].operands[1].value))
                    divisor = self._check_divisor(pow(2, 64+Z+Y), C)
                    X = operand_0.operand.operands[0].operands[0]
        if isinstance(operand_1, Expr.Const) \
                and isinstance(operand_0, Expr.BinaryOp) \
                and operand_0.op == 'Add':
            add_0, add_1 = operand_0.operands
            Z = operand_1.value
            if add_0.has_atom(add_1) or add_1.has_atom(add_0):
                xC = add_1 if add_0.has_atom(add_1) else add_0
                x_xC = add_0 if add_0.has_atom(add_1) else add_1
                if isinstance(xC, Expr.Convert) and (xC.from_bits > xC.to_bits):
                    Y = xC.from_bits - xC.to_bits
                    if isinstance(xC.operand, Expr.BinaryOp) and xC.operand.op == 'Mul':
                        xC_ = xC.operand
                        if isinstance(xC_.operands[1], Expr.Const):
                            C = xC_.operands[1].value
                            X = xC_.operands[0]
                            if isinstance(x_xC, Expr.BinaryOp) and x_xC.op == 'Shr':
                                V_, V = x_xC.operands
                                if isinstance(V, Expr.Const):
                                    V = V.value
                                    if isinstance(V_, Expr.BinaryOp) and V_.op == 'Sub':
                                        if V_.operands[0] == X and V_.operands[1] == xC:
                                            divisor = self._check_divisor(pow(2, Y+V+Z), C*(pow(2, V) - 1) + pow(2, Y))
                # unsigned int here
                if isinstance(xC, Expr.BinaryOp) and xC.op == 'Mul':
                    if isinstance(xC.operands[1], Expr.Const) \
                        and isinstance(xC.operands[0], Expr.Convert):
                        C = xC.operands[1].value
                        X = xC.operands[0]
                        Y = X.from_bits - X.to_bits
                        if isinstance(x_xC, Expr.BinaryOp) and x_xC.op == 'Shr':
                            V_, V = x_xC.operands
                            if isinstance(V, Expr.Const):
                                V = V.value
                                if isinstance(V_, Expr.BinaryOp) and V_.op == 'Sub':
                                    if V_.operands[1] == xC:
                                        divisor = self._check_divisor(pow(2, Y+V+Z), C*(pow(2, V) - 1) + pow(2, Y))
                elif isinstance(xC, Expr.BinaryOp) and xC.op == 'Shr':
                    if isinstance(xC.operands[1], Expr.Const) \
                        and isinstance(xC.operands[0], Expr.BinaryOp) \
                            and xC.operands[0].op == 'Mul' \
                                and isinstance(xC.operands[0].operands[1], Expr.Const):
                        if isinstance(x_xC, Expr.BinaryOp) \
                            and isinstance(x_xC.operands[1], Expr.Const) \
                                and isinstance(x_xC.operands[0], Expr.BinaryOp) \
                                    and x_xC.op == 'Shr' and x_xC.operands[0].op == 'Sub':
                            X = xC.operands[0].operands[0]
                            C = xC.operands[0].operands[1].value
                            Y = xC.operands[1].value
                            V = x_xC.operands[1].value
                            if X == x_xC.operands[0].operands[0]:
                                divisor = self._check_divisor(pow(2, Y+V+Z), C*(pow(2, V) - 1) + pow(2, Y))

        # unsigned int
        if isinstance(operand_1, Expr.Const) \
            and isinstance(operand_0, Expr.BinaryOp) \
                and operand_0.op == 'Mul' \
                    and isinstance(operand_0.operands[1], Expr.Const):
            if isinstance(operand_0.operands[0], Expr.Convert):
                V = operand_0.operands[0].from_bits - operand_0.operands[0].to_bits
                C = operand_0.operands[1].value
                Z = operand_1.value
                X = operand_0.operands[0]
                divisor = self._check_divisor(pow(2, V+Z), C)
            elif isinstance(operand_0.operands[0], Expr.BinaryOp) \
                and isinstance(operand_0.operands[0].operands[1], Expr.Const) \
                    and operand_0.operands[0].op in {'Shr', 'DivMod'}:
                X = operand_0.operands[0].operands[0]
                V = 0
                ndigits = 6
                if isinstance(X, Expr.Convert):
                    V = X.from_bits - X.to_bits
                if V == 32:
                    ndigits = 5
                C = operand_0.operands[1].value
                Y = operand_0.operands[0].operands[1].value
                if operand_0.operands[0].op == 'DivMod':
                    Y = int(math.log2(operand_0.operands[0].operands[1].value))
                Z = operand_1.value
                divisor = self._check_divisor(pow(2, Y+Z+V), C, ndigits)
            else:
                X = operand_0.operands[0]
                Y = operand_1.value
                C = operand_0.operands[1].value
                divisor = self._check_divisor(pow(2, Y), C)

        if divisor and X:
            new_const = Expr.Const(expr.idx, None, divisor, 64)
            return Expr.BinaryOp(expr.idx, 'DivMod', [X, new_const], expr.signed, **expr.tags)

        if isinstance(operand_1, Expr.Const):
            if isinstance(operand_0, Expr.Register):
                new_operand = Expr.Const(operand_1.idx, None, 2**operand_1.value, operand_1.bits)
                return Expr.BinaryOp(expr.idx, 'DivMod', [operand_0, new_operand], expr.signed)
            elif isinstance(operand_0, Expr.BinaryOp) \
                and operand_0.op == 'Shr' \
                    and isinstance(operand_0.operands[1], Expr.Const):
                new_const = Expr.Const(operand_1.idx, None,
                    operand_0.operands[1].value+operand_1.value, operand_1.bits)
                return Expr.BinaryOp(expr.idx, 'Shr', [operand_0.operands[0], new_const], expr.signed, **expr.tags)

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, 'Shr', [operand_0, operand_1], expr.signed)
        return expr

    def _ail_handle_Mul(self, expr):

        operand_0, operand_1 = expr.operands

        if isinstance(operand_1, Expr.Const) \
            and isinstance(operand_0, Expr.BinaryOp) \
                and isinstance(operand_0.operands[1], Expr.Const) \
                    and operand_0.op in {'DivMod', 'Shr'}:
            if operand_0.op == 'DivMod':
                Y = int(math.log2(operand_0.operands[1].value))
            else:
                Y = operand_0.operands[1].value
            C = operand_1.value
            X = operand_0.operands[0]
            # there is a convert outside this expr
            V = 64
            if isinstance(X, Expr.Convert):
                V = X.from_bits - X.to_bits
            ndigits = 5 if V == 32 else 6
            if self._check_divisor(pow(2, V+Y), C, ndigits) and X:
                divisor = self._check_divisor(pow(2, Y+V), C, ndigits)
                new_const = Expr.Const(expr.idx, None, divisor, 64)
                return Expr.BinaryOp(expr.idx, 'DivMod', [X, new_const], expr.signed, **expr.tags)
        if isinstance(operand_1, Expr.Const) \
            and isinstance(operand_0, Expr.Convert) \
                and isinstance(operand_0.operand, Expr.BinaryOp) \
                    and isinstance(operand_0.operand.operands[1], Expr.Const) \
                and operand_0.operand.op in {'DivMod', 'Shr'}:
            if operand_0.operand.op == 'DivMod':
                Y = int(math.log2(operand_0.operand.operands[1].value))
            else:
                Y = operand_0.operand.operands[1].value
            C = operand_1.value
            X = operand_0.operand.operands[0]
            V = operand_0.from_bits - operand_0.to_bits
            ndigits = 5 if V == 32 else 6
            if self._check_divisor(pow(2, V+Y), C, ndigits) and X:
                divisor = self._check_divisor(pow(2, Y+V), C, ndigits)
                new_const = Expr.Const(expr.idx, None, divisor, 64)
                return Expr.BinaryOp(expr.idx, 'DivMod', [X, new_const], expr.signed, **expr.tags)
        return super()._ail_handle_Mul(expr)

    def _ail_handle_Div(self, expr):

        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if isinstance(operand_1, Expr.Const) \
            and isinstance(operand_0, Expr.BinaryOp) \
            and operand_0.op in {'Div', 'DivMod'} \
            and isinstance(operand_0.operands[1], Expr.Const):

            new_const_value = operand_1.value * operand_0.operands[1].value
            new_const = Expr.Const(operand_1.idx, None, new_const_value, operand_1.bits)
            return Expr.BinaryOp(expr.idx, 'Div', [operand_0.operands[0], new_const], expr.signed, **expr.tags)

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return Expr.BinaryOp(expr.idx, 'Div', [operand_0, operand_1], expr.signed, **expr.tags)
        return expr


class DivSimplifier(OptimizationPass):
    """
    Simplifies various division optimizations back to "div".
    """

    ARCHES = ["X86", "AMD64", "ARMCortexM", "ARMHF", "ARMEL", ]
    PLATFORMS = None  #everything
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify arithmetic division"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):

        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.engine = DivSimplifierAILEngine()

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
