# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from typing import Any

import angr
from angr.ailment.expression import Const
from angr.analyses.decompiler.structured_codegen.c import CConstant, CStructuredCodeGenerator
from angr.sim_type import SimTypeInt, SimTypeLongLong
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestFloatConstReferenceValue(unittest.TestCase):
    """
    A Const lifted from a VEX float constant carries a Python float. When the type in hand is already an
    integer type -- a callee prototype declaring an integer parameter, say -- that float used to be stashed
    in CConstant.reference_values under the integer key, and rendering it called hex() on a float and raised
    TypeError, which took the whole function's decompilation with it.

    The codegen is a real one, taken from a decompilation, because CConstant needs a codegen with a project
    and _handle_Expr_Const reads the variable map, the CFG and kb.obfuscations off it.
    """

    def _codegen(self) -> tuple[angr.Project, CStructuredCodeGenerator]:
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg.model)
        codegen = dec.codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        return proj, codegen

    @staticmethod
    def _float_const(value: float, bits: int) -> Const:
        # ailment types Const's value as int; a Const lifted from a VEX float constant holds a float
        float_value: Any = value
        return Const(None, float_value, bits)

    @staticmethod
    def _render(expr) -> str:
        return "".join(chunk for chunk, _ in expr.c_repr_chunks())

    def test_float_const_is_not_an_integer_reference_value(self):
        proj, codegen = self._codegen()
        int_type = SimTypeLongLong(signed=True).with_arch(proj.arch)

        const = codegen._handle_Expr_Const(self._float_const(0.0, 64), type_=int_type)
        assert isinstance(const, CConstant)
        reference_values = const.reference_values or {}
        assert int_type not in reference_values
        assert not [v for v in reference_values.values() if isinstance(v, float)]
        assert self._render(const) == "0.0"

    def test_integer_const_still_gets_a_reference_value(self):
        # the guard above must not cost the integer path the entry it has always had
        proj, codegen = self._codegen()
        int_type = SimTypeLongLong(signed=True).with_arch(proj.arch)

        const = codegen._handle_Expr_Const(Const(None, 17, 64), type_=int_type)
        assert isinstance(const, CConstant)
        assert const.reference_values is not None
        assert const.reference_values[int_type] == 17

    def test_a_stashed_float_still_renders(self):
        # nothing in the tree should put one here any more, but a cached or hand-built CConstant can, and the
        # reader used to answer that with hex() -- a call that cannot succeed for any value that reaches it
        proj, codegen = self._codegen()
        int_type = SimTypeLongLong(signed=True).with_arch(proj.arch)

        const = CConstant(0.0, int_type, reference_values={int_type: 0.0}, codegen=codegen)

        # the three conditions that used to reach hex(), asserted so this cannot pass by missing the branch
        assert const.reference_values is not None
        assert isinstance(const._type, SimTypeInt)
        assert const._type in const.reference_values
        assert not isinstance(const.reference_values[const._type], int)

        assert self._render(const) == "0.0"


if __name__ == "__main__":
    unittest.main()
