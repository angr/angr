# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""Smoke tests for the Expression marker classes."""

from __future__ import annotations

import unittest

import angr.ailment.expression as spike
from angr.ailment.statement import Assignment, Label
from angr.rustylib.ailment import (  # pylint:disable=import-error,no-name-in-module
    Expression,
    ExpressionKind,
    StatementKind,
    VirtualVariableCategory,
)


class TestExpressionMarkers(unittest.TestCase):
    """Per-variant construction + ``isinstance`` dispatch + roundtrip."""

    def _roundtrip(self, expr) -> Expression:
        return Expression.from_bytes(expr.to_bytes())

    def test_const(self):
        c = spike.Const(0, 42, 32)
        assert c.kind == ExpressionKind.Const
        assert isinstance(c, spike.Const)
        assert not isinstance(c, spike.Tmp)
        assert c.value == 42 and c.bits == 32

    def test_tmp(self):
        t = spike.Tmp(0, 5, 64)
        assert isinstance(t, spike.Tmp) and t.tmp_idx == 5

    def test_register(self):
        r = spike.Register(0, 16, 64)
        assert isinstance(r, spike.Register) and r.reg_offset == 16

    def test_combo_register(self):
        r1 = spike.Register(0, 16, 32)
        r2 = spike.Register(1, 20, 32)
        cr = spike.ComboRegister(2, [r1, r2])
        assert isinstance(cr, spike.ComboRegister)
        assert len(cr.registers) == 2 and cr.bits == 64

    def test_phi(self):
        v1 = spike.VirtualVariable(0, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
        p = spike.Phi(1, 32, [((0, None), v1)])
        assert isinstance(p, spike.Phi)
        assert hash(p) is not None  # was the legacy regression

    def test_virtual_variable(self):
        v = spike.VirtualVariable(0, 5, 64, VirtualVariableCategory.REGISTER, oident=16)
        assert isinstance(v, spike.VirtualVariable)
        assert v.varid == 5 and v.was_reg and v.reg_offset == 16

    def test_unary_op(self):
        c = spike.Const(0, 1, 32)
        u = spike.UnaryOp(1, "Neg", c)
        assert isinstance(u, spike.UnaryOp) and u.op == "Neg"

    def test_convert(self):
        c = spike.Const(0, 1, 32)
        cv = spike.Convert(1, 32, 64, False, c)
        assert isinstance(cv, spike.Convert) and cv.from_bits == 32 and cv.to_bits == 64

    def test_reinterpret(self):
        c = spike.Const(0, 1, 32)
        r = spike.Reinterpret(1, 32, "I", 32, "F", c)
        assert isinstance(r, spike.Reinterpret)

    def test_binary_op(self):
        c1 = spike.Const(0, 1, 32)
        c2 = spike.Const(1, 2, 32)
        b = spike.BinaryOp(2, "Add", (c1, c2))
        assert isinstance(b, spike.BinaryOp) and b.op == "Add"

    def test_load(self):
        addr = spike.Const(0, 0x1000, 64)
        ld = spike.Load(1, addr, 8, "Iend_LE")
        assert isinstance(ld, spike.Load) and ld.endness == "Iend_LE"

    def test_call(self):
        c = spike.Const(0, 0x400500, 64)
        arg = spike.Const(1, 7, 32)
        call = spike.Call(2, c, args=(arg,), bits=64)
        assert isinstance(call, spike.Call)
        assert len(call.args) == 1 and call.op == "call"

    def test_ite(self):
        c = spike.Const(0, 1, 1)
        t = spike.Const(1, 10, 32)
        f = spike.Const(2, 20, 32)
        i = spike.ITE(3, c, f, t)
        assert isinstance(i, spike.ITE)

    def test_extract(self):
        b = spike.Const(0, 0xFF, 32)
        o = spike.Const(1, 0, 32)
        e = spike.Extract(2, 8, b, o, "Iend_LE")
        assert isinstance(e, spike.Extract)

    def test_insert(self):
        b = spike.Const(0, 0xFF, 32)
        o = spike.Const(1, 0, 32)
        v = spike.Const(2, 0xAA, 8)
        i = spike.Insert(3, b, o, v, "Iend_LE")
        assert isinstance(i, spike.Insert)

    def test_string_literal(self):
        s = spike.StringLiteral(0, "hello", 40)
        assert isinstance(s, spike.StringLiteral) and s.data == "hello"

    def test_base_pointer_offset(self):
        b = spike.BasePointerOffset(0, 64, "base", 16)
        assert isinstance(b, spike.BasePointerOffset)

    def test_stack_base_offset(self):
        s = spike.StackBaseOffset(0, 64, -32)
        assert isinstance(s, spike.StackBaseOffset) and s.offset == -32

    def test_dirty_expression(self):
        c1 = spike.Const(0, 1, 32)
        d = spike.DirtyExpression(1, "helper_x86_calc_cf", [c1], bits=32)
        assert isinstance(d, spike.DirtyExpression)
        assert d.callee == "helper_x86_calc_cf" and d.op == "helper_x86_calc_cf"

    def test_vex_ccall_expression(self):
        c1 = spike.Const(0, 1, 32)
        v = spike.VEXCCallExpression(1, "helper_x86_F", (c1,), 32)
        assert isinstance(v, spike.VEXCCallExpression)

    def test_multi_statement_expression(self):
        c1 = spike.Const(0, 1, 32)
        mse = spike.MultiStatementExpression(1, [], c1)
        assert isinstance(mse, spike.MultiStatementExpression)
        assert mse.expr is not None

    def test_multi_statement_expression_with_real_statements(self):
        """MSE.stmts holds real Statement instances and round-trips with
        full fidelity."""
        dst = spike.Register(0, 16, 64)
        src = spike.Const(1, 42, 64)
        final = spike.Const(2, 7, 32)
        a = Assignment(3, dst, src)
        lbl = Label(4, "L1")
        mse = spike.MultiStatementExpression(5, [a, lbl], final)
        assert isinstance(mse, spike.MultiStatementExpression)
        stmts = list(mse.stmts)
        assert len(stmts) == 2
        assert stmts[0].kind == StatementKind.Assignment
        assert stmts[1].kind == StatementKind.Label
        r = self._roundtrip(mse)
        assert str(r) == str(mse)

    def test_struct(self):
        c1 = spike.Const(0, 1, 32)
        s = spike.Struct(1, "Foo", {0: c1}, {"a": 0}, 32)
        assert isinstance(s, spike.Struct)
        assert s.name == "Foo" and s.get_field("a") is not None

    def test_rust_enum(self):
        c1 = spike.Const(0, 1, 32)
        re_ = spike.RustEnum(1, "Option", [c1], 32)
        assert isinstance(re_, spike.RustEnum) and re_.name == "Option"

    def test_array(self):
        c1 = spike.Const(0, 1, 32)
        arr = spike.Array(1, [c1], 32)
        assert isinstance(arr, spike.Array) and arr.length == 1

    def test_let(self):
        c1 = spike.Const(0, 1, 32)
        ll = spike.Let(1, [], c1)
        assert isinstance(ll, spike.Let) and ll.op == "let"

    def test_macro(self):
        m = spike.Macro(0, "println")
        assert isinstance(m, spike.Macro)
        # Legacy: Macro is-a Call
        assert isinstance(m, spike.Call)
        # Compatibility getter
        assert m.arg_vvars is None

    def test_function_like_macro(self):
        c1 = spike.Const(0, 1, 32)
        flm = spike.FunctionLikeMacro(1, "format", [c1])
        assert isinstance(flm, spike.FunctionLikeMacro)
        # Legacy: FunctionLikeMacro is-a Macro is-a Call
        assert isinstance(flm, spike.Macro)
        assert isinstance(flm, spike.Call)

    def test_metaclass_does_not_match_unrelated(self):
        c = spike.Const(0, 1, 32)
        # Const should not match unrelated markers
        for marker in [
            spike.Tmp,
            spike.BinaryOp,
            spike.Load,
            spike.Call,
            spike.Macro,
            spike.Struct,
            spike.Array,
        ]:
            assert not isinstance(c, marker), f"Const matched {marker.__name__}"

    def test_roundtrip_all_variants(self):
        """Every variant must round-trip through to_bytes/from_bytes."""
        c1 = spike.Const(0, 1, 32)
        c2 = spike.Const(1, 2, 32)
        addr = spike.Const(2, 0x1000, 64)

        all_exprs = [
            c1,
            spike.Tmp(0, 5, 64),
            spike.Register(0, 16, 64),
            spike.ComboRegister(0, [spike.Register(0, 16, 32), spike.Register(1, 20, 32)]),
            spike.VirtualVariable(0, 5, 64, VirtualVariableCategory.REGISTER, oident=16),
            spike.UnaryOp(0, "Neg", c1),
            spike.Convert(0, 32, 64, False, c1),
            spike.Reinterpret(0, 32, "I", 32, "F", c1),
            spike.BinaryOp(0, "Add", (c1, c2)),
            spike.Load(0, addr, 8, "Iend_LE"),
            spike.Call(0, c1, args=(c2,), bits=64),
            spike.ITE(0, c1, c2, c1),
            spike.Extract(0, 8, c1, c2, "Iend_LE"),
            spike.Insert(0, c1, c2, c1, "Iend_LE"),
            spike.StringLiteral(0, "x", 8),
            spike.BasePointerOffset(0, 64, "base", 0),
            spike.StackBaseOffset(0, 64, -32),
            spike.DirtyExpression(0, "h", [c1], bits=32),
            spike.VEXCCallExpression(0, "h", (c1,), 32),
            spike.MultiStatementExpression(0, [], c1),
            spike.Struct(0, "F", {0: c1}, {"a": 0}, 32),
            spike.RustEnum(0, "E", [c1], 32),
            spike.Array(0, [c1], 32),
            spike.Macro(0, "m"),
            spike.FunctionLikeMacro(0, "m", [c1]),
        ]
        for e in all_exprs:
            r = self._roundtrip(e)
            assert r.kind == e.kind, f"kind mismatch: {e.kind} != {r.kind}"


if __name__ == "__main__":
    unittest.main()
