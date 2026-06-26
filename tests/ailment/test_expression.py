# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from collections import OrderedDict
from types import SimpleNamespace

import pytest

import angr.ailment as ailment
from angr.ailment.expression import (
    Array,
    ComboRegister,
    Const,
    FunctionLikeMacro,
    Let,
    Register,
    RustEnum,
    StringLiteral,
    Struct,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.sim_type import SimTypeBottom


class TestExpression(unittest.TestCase):
    def test_phi_hashing(self):
        vvar_0 = ailment.expression.VirtualVariable(100, 0, 32, ailment.expression.VirtualVariableCategory.REGISTER, 16)
        vvar_1 = ailment.expression.VirtualVariable(101, 1, 32, ailment.expression.VirtualVariableCategory.REGISTER, 16)
        vvar_2 = ailment.expression.VirtualVariable(102, 2, 32, ailment.expression.VirtualVariableCategory.REGISTER, 16)
        phi_expr = ailment.expression.Phi(
            0, 32, [((0, None), vvar_0), ((0, 0), vvar_2), ((1, None), vvar_1), ((4, None), None)]
        )
        h = hash(phi_expr)  # should not crash
        assert h is not None

    def test_rust_composite_return_deep_copy(self):
        field = ailment.expression.VirtualVariable(
            100,
            0,
            64,
            ailment.expression.VirtualVariableCategory.STACK,
            oident=-8,
        )
        struct_expr = ailment.expression.Struct(
            101,
            "struct1",
            OrderedDict([(0, field)]),
            OrderedDict([("field_0", 0)]),
            64,
            ins_addr=0x400000,
        )
        enum_expr = ailment.expression.RustEnum(102, "Ok", [struct_expr], 64, ins_addr=0x400001)
        ret_stmt = ailment.statement.Return(103, [enum_expr])

        copied = ret_stmt.deep_copy(ailment.Manager())
        copied_enum = copied.ret_exprs[0]
        assert isinstance(copied_enum, ailment.expression.RustEnum)
        copied_struct = copied_enum.fields[0]
        assert isinstance(copied_struct, ailment.expression.Struct)

        assert copied is not ret_stmt
        assert copied_enum is not enum_expr
        assert copied_struct is not struct_expr
        assert copied_struct.fields[0] is not field
        assert copied_struct.fields[0].likes(field)
        assert copied_enum.tags == enum_expr.tags
        assert copied_struct.tags == struct_expr.tags

    def test_combo_register_and_virtual_variable_accessors(self):
        reg0 = Register(0, 16, 64, reg_name="rax")
        reg1 = Register(1, 24, 64, reg_name="rdx")
        combo = ComboRegister(2, [reg0, reg1])

        assert combo.size == 16
        assert "ComboRegister" in str(combo)
        assert combo.likes(ComboRegister(3, [reg0.copy(), reg1.copy()]))
        assert combo.matches(combo.copy())
        assert hash(combo) == hash(combo)

        combo_vvar = VirtualVariable(4, 10, 128, VirtualVariableCategory.COMBO_REGISTER, oident=(16, 24))
        reg_param = VirtualVariable(
            5,
            11,
            64,
            VirtualVariableCategory.PARAMETER,
            oident=(VirtualVariableCategory.REGISTER, 16),
        )
        stack_param = VirtualVariable(
            6,
            12,
            64,
            VirtualVariableCategory.PARAMETER,
            oident=(VirtualVariableCategory.STACK, -8),
        )
        combo_param = VirtualVariable(
            7,
            13,
            128,
            VirtualVariableCategory.PARAMETER,
            oident=(VirtualVariableCategory.COMBO_REGISTER, (16, 24)),
        )
        tmp_vvar = VirtualVariable(8, 14, 32, VirtualVariableCategory.TMP, oident=2)

        assert combo_vvar.was_combo_reg
        assert combo_vvar.reg_offsets == (16, 24)
        assert reg_param.reg_offset == 16
        assert stack_param.stack_offset == -8
        assert combo_param.reg_offsets == (16, 24)
        assert tmp_vvar.tmp_idx == 2
        assert tmp_vvar.parameter_category is None
        assert reg_param.parameter_reg_offset == 16
        assert stack_param.parameter_stack_offset == -8
        assert "combo_reg" in repr(combo_vvar)

        with pytest.raises(TypeError):
            _ = stack_param.reg_offset
        with pytest.raises(TypeError):
            _ = reg_param.stack_offset

    def test_rust_ail_value_expressions(self):
        manager = ailment.Manager()
        old = Const(0, 1, 32)
        new = Const(1, 2, 32)

        literal = StringLiteral(2, b"hello\n", 48, tag="literal")
        assert literal.size == 6
        assert "hello\\n" in repr(literal)
        assert str(literal).startswith("StringLiteral")
        assert literal.likes(StringLiteral(3, b"hello\n", 48))
        assert literal.copy().tags == literal.tags
        assert literal.deep_copy(manager).idx != literal.idx
        replaced, replacement = literal.replace(StringLiteral(4, b"hello\n", 48), new)
        assert replaced and replacement is new
        replaced, replacement = literal.replace(StringLiteral(5, b"bye", 24), new)
        assert not replaced and replacement is literal

        nested = Struct(6, "inner", OrderedDict([(0, old)]), OrderedDict([("value", 0)]), 32)
        outer = Struct(7, "outer", OrderedDict([(0, nested)]), OrderedDict([("inner", 0)]), 32)
        assert outer.get_field("inner.value") is old
        assert outer.get_field("missing") is None
        assert outer.size == 4
        assert "outer" in str(outer)
        assert outer.likes(outer.copy())
        replaced, new_outer = outer.replace(old, new)
        assert replaced
        assert new_outer.get_field("inner.value") is new
        assert not outer.replace(Const(8, 99, 32), new)[0]

        enum_expr = RustEnum(9, "Ok", [old], 32)
        assert enum_expr.size == 4
        assert str(enum_expr).startswith("Ok")
        assert enum_expr.likes(enum_expr.copy())
        assert enum_expr.deep_copy(manager).fields[0] is not old
        replaced, new_enum = enum_expr.replace(old, new)
        assert replaced and new_enum.fields[0] is new
        tuple_enum = RustEnum(10, "Tuple", (old,), 32)
        assert isinstance(tuple_enum.deep_copy(manager).fields, tuple)

        array_expr = Array(11, [old], 32)
        assert array_expr.length == 1
        assert array_expr.size == 4
        assert array_expr.likes(array_expr.copy())
        assert array_expr.deep_copy(manager).elements[0] is not old
        replaced, new_array = array_expr.replace(old, new)
        assert replaced and new_array.elements[0] is new
        tuple_array = Array(12, (old,), 32)
        assert isinstance(tuple_array.deep_copy(manager).elements, tuple)

        # ``variant`` and ``returnty`` now live in the VariableMap, keyed by the expression's .idx.
        vmap = variable_map_of(manager)

        variant = SimpleNamespace(name="Some")
        let_expr = Let(13, [Assignment(14, VirtualVariable(15, 1, 32, VirtualVariableCategory.REGISTER, 16), old)], old)
        vmap.set_variant(let_expr, variant)
        assert vmap.variant(let_expr) is variant
        assert "let (_)" in str(let_expr)
        assert let_expr.likes(let_expr.copy())
        let_dc = let_expr.deep_copy(manager)
        assert let_dc.src is not old  # type:ignore
        assert vmap.variant(let_dc) is variant  # transferred to the new .idx

        returnty = SimTypeBottom(label="usize")
        macro = FunctionLikeMacro(16, "format", [old], bits=64, delimiter="[]")
        vmap.set_returnty(macro, returnty)
        assert vmap.returnty(macro) is returnty
        assert macro.size == 8
        assert macro.op == "macro_call"
        assert macro.verbose_op == "macro_call"
        assert "format!" in str(macro)
        assert "Macro" in repr(macro)
        assert macro.likes(FunctionLikeMacro(17, "format", [old.copy()], bits=64, delimiter="[]"))
        assert macro.copy().args == macro.args
        macro_dc = macro.deep_copy(manager)
        assert macro_dc.args[0] is not old  # type:ignore
        assert vmap.returnty(macro_dc) is returnty  # transferred to the new .idx
        assert FunctionLikeMacro(18, "dbg", None).deep_copy(manager).args is None


class TestIRegister(unittest.TestCase):
    """Unit tests for IRegister expression type."""

    def _make_ireg(self, ix_value, bits=64, base=904, bias=0, n_elems=8, shift=3):
        """Create an IRegister with a Const reg_offset."""
        ix = ailment.expression.Const(1, ix_value, 32)
        return ailment.expression.IRegister(
            2, ix, bits, array_base=base, array_bias=bias, array_nElems=n_elems, array_shift=shift
        )

    def test_concrete_reg_offset_zero(self):
        ireg = self._make_ireg(0)
        assert ireg.concrete_reg_offset() == 904  # base + ((0+0)%8)<<3

    def test_concrete_reg_offset_wrapped(self):
        """ftop = -1 (0xffffffff as unsigned 32-bit)."""
        ireg = self._make_ireg(0xFFFFFFFF)
        # -1 % 8 = 7; base + 7*8 = 904 + 56 = 960 (mm7)
        assert ireg.concrete_reg_offset() == 960

    def test_concrete_reg_offset_seven(self):
        ireg = self._make_ireg(7)
        assert ireg.concrete_reg_offset() == 904 + 7 * 8

    def test_concrete_reg_offset_fptag(self):
        """fptag array: base=968, shift=0 (1-byte elements)."""
        ireg = self._make_ireg(0xFFFFFFFF, bits=8, base=968, shift=0)
        assert ireg.concrete_reg_offset() == 968 + 7

    def test_concrete_reg_offset_non_const(self):
        """Non-Const reg_offset should return None."""
        tmp = ailment.expression.Tmp(1, 5, 32)
        ireg = ailment.expression.IRegister(2, tmp, 64, array_base=904, array_nElems=8, array_shift=3)
        assert ireg.concrete_reg_offset() is None

    def test_size(self):
        ireg = self._make_ireg(0, bits=64)
        assert ireg.size == 8
        ireg32 = self._make_ireg(0, bits=32)
        assert ireg32.size == 4

    def test_str_no_variable(self):
        ireg = self._make_ireg(0, bits=64)
        s = str(ireg)
        assert "ireg_" in s

    def test_replace_match(self):
        old_ix = ailment.expression.Const(1, 5, 32)
        ireg = ailment.expression.IRegister(2, old_ix, 64, array_base=904, array_nElems=8, array_shift=3)
        new_ix = ailment.expression.Const(3, 0xFFFFFFFF, 32)
        replaced, result = ireg.replace(old_ix, new_ix)
        assert replaced
        assert result.reg_offset is new_ix
        assert result.array_base == 904

    def test_replace_no_match(self):
        ireg = self._make_ireg(0)
        other = ailment.expression.Const(99, 42, 32)
        new = ailment.expression.Const(100, 99, 32)
        replaced, result = ireg.replace(other, new)
        assert not replaced
        assert result is ireg

    def test_replace_self(self):
        ireg = self._make_ireg(0)
        new = ailment.expression.Const(99, 42, 32)
        replaced, result = ireg.replace(ireg, new)
        assert replaced
        assert result is new

    def test_copy_preserves_descriptor(self):
        ireg = self._make_ireg(3, bits=64, base=904, bias=1, n_elems=8, shift=3)
        c = ireg.copy()
        assert c.array_base == 904
        assert c.array_bias == 1
        assert c.array_nElems == 8
        assert c.array_shift == 3
        assert c.bits == 64
        assert c is not ireg

    def test_deep_copy_preserves_descriptor(self):
        from angr.ailment.manager import Manager

        mgr = Manager(arch=None)
        ireg = self._make_ireg(3, bits=64, base=968, bias=0, n_elems=8, shift=0)
        dc = ireg.deep_copy(mgr)
        assert dc.array_base == 968
        assert dc.array_shift == 0
        assert dc.reg_offset is not ireg.reg_offset  # deep copied
        assert dc.idx != ireg.idx  # new atom id

    def test_likes(self):
        a = self._make_ireg(5)
        b = self._make_ireg(5)
        c = self._make_ireg(6)
        assert a.likes(b)
        assert not a.likes(c)

    def test_hash(self):
        ireg = self._make_ireg(0)
        s = {ireg}
        assert ireg in s


class TestConvertFPTypes(unittest.TestCase):
    """Tests for FP type tracking in Convert expressions."""

    def test_convert_fp_type_tags(self):
        inner = ailment.expression.Const(None, 42, 32)
        conv = ailment.expression.Convert(
            None,
            32,
            64,
            False,
            inner,
            from_type=ailment.expression.Convert.TYPE_INT,
            to_type=ailment.expression.Convert.TYPE_FP,
        )
        assert conv.from_type == ailment.expression.Convert.TYPE_INT
        assert conv.to_type == ailment.expression.Convert.TYPE_FP
        assert conv.tags.get("_from_type") == ailment.expression.Convert.TYPE_INT
        assert conv.tags.get("_to_type") == ailment.expression.Convert.TYPE_FP

    def test_convert_type_preserved_in_copy(self):
        inner = ailment.expression.Const(None, 42, 32)
        conv = ailment.expression.Convert(
            None,
            32,
            64,
            False,
            inner,
            from_type=ailment.expression.Convert.TYPE_INT,
            to_type=ailment.expression.Convert.TYPE_FP,
        )
        conv_copy = conv.copy()
        assert conv_copy.from_type == ailment.expression.Convert.TYPE_INT
        assert conv_copy.to_type == ailment.expression.Convert.TYPE_FP

    def test_convert_default_types(self):
        inner = ailment.expression.Const(None, 42, 32)
        conv = ailment.expression.Convert(None, 32, 64, False, inner)
        assert conv.from_type == ailment.expression.Convert.TYPE_INT
        assert conv.to_type == ailment.expression.Convert.TYPE_INT


class TestBinaryOpFloatingPoint(unittest.TestCase):
    """Tests for floating_point flag on BinaryOp expressions."""

    def test_binaryop_floating_point_flag(self):
        a = ailment.expression.Const(None, 42, 64)
        b = ailment.expression.Const(None, 43, 64)
        op = ailment.expression.BinaryOp(None, "Fadd", [a, b], False, floating_point=True)
        assert op.floating_point is True
        assert op.tags.get("_floating_point") is True

    def test_binaryop_floating_point_preserved_in_tags(self):
        a = ailment.expression.Const(None, 42, 64)
        b = ailment.expression.Const(None, 43, 64)
        op = ailment.expression.BinaryOp(None, "Fadd", [a, b], False, floating_point=True)
        op_copy = op.copy()
        assert op_copy.floating_point is True

    def test_binaryop_not_floating_point_by_default(self):
        a = ailment.expression.Const(None, 42, 64)
        b = ailment.expression.Const(None, 43, 64)
        op = ailment.expression.BinaryOp(None, "Add", [a, b], False)
        assert op.floating_point is False


if __name__ == "__main__":
    unittest.main()
