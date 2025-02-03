from __future__ import annotations
from typing import Generic, TypeVar
from collections.abc import Callable
import claripy
from pyvex.expr import IRExpr, Unop, get_op_retty, Binop
from pyvex.const import get_type_size

from angr.utils.bits import zeroextend_on_demand
from angr.block import Block
from angr.engines.engine import DataType_co
from angr.engines.light.engine import SimEngineLight, SimEngineLightVEX, StateType, BlockType, ResultType, StmtDataType

TOPS: dict[int, claripy.ast.BV] = {}

T = TypeVar("T")


class ClaripyDataEngineMixin(
    Generic[StateType, DataType_co, BlockType, ResultType],
    SimEngineLight[StateType, DataType_co | claripy.ast.BV, BlockType, ResultType],
):
    def _is_top(self, expr) -> bool:
        return "TOP" in expr.variables

    def _top(self, bits: int) -> DataType_co | claripy.ast.BV:
        if bits in TOPS:
            return TOPS[bits]
        r = claripy.BVS("TOP", bits, explicit_name=True)
        TOPS[bits] = r
        return r


def _vex_make_comparison(
    func: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.Bool],
) -> Callable[[ClaripyDataEngineMixin, Binop], claripy.ast.BV]:
    @SimEngineLightVEX.binop_handler
    def inner(self, expr):
        a, b = self._expr(expr.args[0]), self._expr(expr.args[1])
        if self._is_top(a) or self._is_top(b):
            return self._top(1)
        return claripy.If(func(a, b), claripy.BVV(1, 1), claripy.BVV(0, 1))

    return inner


def _vex_make_vec_comparison(
    func: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.Bool],
) -> Callable[[ClaripyDataEngineMixin, int, int, Binop], claripy.ast.BV]:
    @SimEngineLightVEX.binopv_handler
    def inner(self, size, count, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        fullsize = get_type_size(get_op_retty(expr.op))
        return self._top(fullsize)

    return inner


def _vex_make_operation(
    func: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.BV],
) -> Callable[[ClaripyDataEngineMixin, Binop], claripy.ast.BV]:
    @SimEngineLightVEX.binop_handler
    def inner(self, expr: Binop):
        a, b = self._expr(expr.args[0]), self._expr(expr.args[1])
        if self._is_top(a) or self._is_top(b):
            fullsize = get_type_size(get_op_retty(expr.op))
            return self._top(fullsize)
        return func(a, b)

    return inner


def _vex_make_unary_operation(
    func: Callable[[claripy.ast.BV], claripy.ast.BV],
) -> Callable[[ClaripyDataEngineMixin, Unop], claripy.ast.BV]:
    @SimEngineLightVEX.unop_handler
    def inner(self, expr):
        a = self._expr(expr.args[0])
        if self._is_top(a):
            fullsize = get_type_size(get_op_retty(expr.op))
            return self._top(fullsize)
        return func(a)

    return inner


def _vex_make_shift_operation(
    func: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.BV],
) -> Callable[[ClaripyDataEngineMixin, Binop], claripy.ast.BV]:
    @_vex_make_operation
    def inner(a, b):
        if b.size() < a.size():
            b = claripy.ZeroExt(a.size() - b.size(), b)
        elif b.size() > a.size():
            b = claripy.Extract(a.size() - 1, 0, b)

        return func(a, b)

    return inner


def _vex_make_vec_operation(
    func: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.BV],
) -> Callable[[ClaripyDataEngineMixin, int, int, Binop], claripy.ast.BV]:
    @SimEngineLightVEX.binopv_handler
    def inner(self, size, count, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        fullsize = get_type_size(get_op_retty(expr.op))
        return self._top(fullsize)

    return inner


class ClaripyDataVEXEngineMixin(
    Generic[StateType, DataType_co, ResultType, StmtDataType],
    ClaripyDataEngineMixin[StateType, DataType_co, Block, ResultType],
    SimEngineLightVEX[StateType, DataType_co | claripy.ast.BV, ResultType, StmtDataType],
):
    def _expr_bv(self, expr: IRExpr) -> claripy.ast.BV:
        result = self._expr(expr)
        assert isinstance(result, claripy.ast.BV)
        return result

    def _expr_fp(self, expr: IRExpr) -> claripy.ast.FP:
        result = self._expr(expr)
        assert isinstance(result, claripy.ast.FP)
        return result

    _handle_binop_CmpEQ = _vex_make_comparison(lambda a, b: a == b)
    _handle_binop_CmpNE = _vex_make_comparison(lambda a, b: a != b)
    _handle_binop_CmpLT = _vex_make_comparison(lambda a, b: a < b)
    _handle_binop_CmpGT = _vex_make_comparison(lambda a, b: a > b)
    _handle_binop_CmpLE = _vex_make_comparison(lambda a, b: a <= b)
    _handle_binop_CmpGE = _vex_make_comparison(lambda a, b: a >= b)

    _handle_binopv_CmpEQ = _vex_make_vec_comparison(lambda a, b: a == b)
    _handle_binopv_CmpNE = _vex_make_vec_comparison(lambda a, b: a != b)
    _handle_binopv_CmpLT = _vex_make_vec_comparison(lambda a, b: a < b)
    _handle_binopv_CmpGT = _vex_make_vec_comparison(lambda a, b: a > b)
    _handle_binopv_CmpLE = _vex_make_vec_comparison(lambda a, b: a <= b)
    _handle_binopv_CmpGE = _vex_make_vec_comparison(lambda a, b: a >= b)

    _handle_unop_Neg = _vex_make_unary_operation(lambda a: -a)
    _handle_unop_Not = _vex_make_unary_operation(lambda a: ~a)

    _handle_binop_Add = _vex_make_operation(lambda a, b: a + b)
    _handle_binop_Sub = _vex_make_operation(lambda a, b: a - b)
    _handle_binop_Mul = _vex_make_operation(lambda a, b: a * b)
    _handle_binop_MullS = _vex_make_operation(lambda a, b: a.sign_extend(a.size()) * b.sign_extend(b.size()))
    _handle_binop_MullU = _vex_make_operation(lambda a, b: a.zero_extend(a.size()) * b.zero_extend(b.size()))
    _handle_binop_And = _vex_make_operation(lambda a, b: a & b)
    _handle_binop_Or = _vex_make_operation(lambda a, b: a | b)
    _handle_binop_Xor = _vex_make_operation(lambda a, b: a ^ b)
    _handle_binop_Shl = _vex_make_shift_operation(lambda a, b: a << zeroextend_on_demand(a, b))
    _handle_binop_Sar = _vex_make_shift_operation(lambda a, b: a >> zeroextend_on_demand(a, b))
    _handle_binop_Shr = _vex_make_shift_operation(lambda a, b: claripy.LShR(a, zeroextend_on_demand(a, b)))

    @SimEngineLightVEX.binop_handler
    def _handle_binop_Div(self, expr):
        a, b = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        if self._is_top(a) or self._is_top(b) or (b == 0).is_true():
            fullsize = get_type_size(get_op_retty(expr.op))
            return self._top(fullsize)
        return a // b

    @SimEngineLightVEX.binop_handler
    def _handle_binop_Mod(self, expr):
        a, b = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        if self._is_top(a) or self._is_top(b) or (b == 0).is_true():
            fullsize = get_type_size(get_op_retty(expr.op))
            return self._top(fullsize)
        return a % b

    @SimEngineLightVEX.binop_handler
    def _handle_binop_DivMod(self, expr):
        a, b = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        if self._is_top(a) or self._is_top(b) or (b == 0).is_true():
            fullsize = get_type_size(get_op_retty(expr.op))
            return self._top(fullsize)

        signed = "U" in expr.op  # Iop_DivModU64to32 vs Iop_DivMod
        from_size = a.size()
        to_size = b.size()
        if signed:
            quotient = a.SDiv(claripy.SignExt(from_size - to_size, b))
            remainder = a.SMod(claripy.SignExt(from_size - to_size, b))
            quotient_size = to_size
            remainder_size = to_size
            return claripy.Concat(
                claripy.Extract(remainder_size - 1, 0, remainder), claripy.Extract(quotient_size - 1, 0, quotient)
            )
        quotient = a // claripy.ZeroExt(from_size - to_size, b)
        remainder = a % claripy.ZeroExt(from_size - to_size, b)
        quotient_size = to_size
        remainder_size = to_size
        return claripy.Concat(
            claripy.Extract(remainder_size - 1, 0, remainder), claripy.Extract(quotient_size - 1, 0, quotient)
        )

    _handle_binop_64HLto128 = _vex_make_operation(claripy.Concat)
    _handle_binop_32HLto64 = _vex_make_operation(claripy.Concat)
    _handle_binop_16HLto32 = _vex_make_operation(claripy.Concat)
    _handle_binop_8HLto16 = _vex_make_operation(claripy.Concat)

    def _handle_conversion(self, from_size, to_size, signed, operand):
        expr_ = self._expr_bv(operand)
        assert from_size == operand.result_size(self.tyenv)
        if self._is_top(expr_):
            return self._top(to_size).annotate(*expr_.annotations)

        if expr_.size() > to_size:
            # truncation
            return expr_[to_size - 1 : 0]
        if expr_.size() < to_size:
            # extension
            if signed:
                return claripy.SignExt(to_size - expr_.size(), expr_)
            return claripy.ZeroExt(to_size - expr_.size(), expr_)
        return expr_
