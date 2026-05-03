# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations
from collections import OrderedDict
import unittest

import angr.ailment as ailment


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


if __name__ == "__main__":
    unittest.main()
