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

        literal = StringLiteral(2, "hello\n", 48, tag="literal")
        assert literal.size == 6
        assert "hello\\n" in repr(literal)
        assert str(literal).startswith("StringLiteral")
        assert literal.likes(StringLiteral(3, "hello\n", 48))
        assert literal.copy().tags == literal.tags
        assert literal.deep_copy(manager).idx != literal.idx
        replaced, replacement = literal.replace(StringLiteral(4, "hello\n", 48), new)
        assert replaced and replacement is new
        replaced, replacement = literal.replace(StringLiteral(5, "bye", 24), new)
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
        # Phase D: getters materialize a fresh ``Expression`` wrapper, so
        # ``is new`` identity through replace doesn't survive into nested
        # containers. Use structural equality (``likes``) instead.
        assert new_outer.get_field("inner.value").likes(new)
        assert not outer.replace(Const(8, 99, 32), new)[0]

        enum_expr = RustEnum(9, "Ok", [old], 32)
        assert enum_expr.size == 4
        assert str(enum_expr).startswith("Ok")
        assert enum_expr.likes(enum_expr.copy())
        # ``deep_copy`` should give the child a fresh ``idx``; Phase D
        # materializes a fresh wrapper on every accessor so ``is not`` no
        # longer applies. Check ``idx`` differs instead.
        assert enum_expr.deep_copy(manager).fields[0].idx != old.idx
        replaced, new_enum = enum_expr.replace(old, new)
        assert replaced and new_enum.fields[0].likes(new)
        # Phase D: ``RustEnum.fields`` is now stored as ``Vec<Box<AilExpression>>``
        # internally; the getter always returns a list regardless of the
        # iterable passed to the constructor.
        tuple_enum = RustEnum(10, "Tuple", (old,), 32)
        assert isinstance(tuple_enum.deep_copy(manager).fields, list)

        array_expr = Array(11, [old], 32)
        assert array_expr.length == 1
        assert array_expr.size == 4
        assert array_expr.likes(array_expr.copy())
        assert array_expr.deep_copy(manager).elements[0].idx != old.idx
        replaced, new_array = array_expr.replace(old, new)
        assert replaced and new_array.elements[0].likes(new)
        # Phase D: ``Array.elements`` is now stored as ``Vec<Box<AilExpression>>``
        # internally; the getter always returns a list regardless of the
        # iterable passed to the constructor.
        tuple_array = Array(12, (old,), 32)
        assert isinstance(tuple_array.deep_copy(manager).elements, list)

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


if __name__ == "__main__":
    unittest.main()
