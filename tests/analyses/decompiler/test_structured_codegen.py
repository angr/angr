#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CFakeVariable
from angr.sim_type import SimTypeChar, TypeRef


class TestConvertRendering(unittest.TestCase):
    """How CStructuredCodeGenerator renders Convert expressions of assorted widths."""

    @classmethod
    def setUpClass(cls):
        # any decompilation will do; all we need is a codegen instance to render expressions with
        proj = angr.load_shellcode(b"\x31\xc0\xc3", arch="AMD64")  # xor eax, eax; ret
        cfg = proj.analyses.CFGFast(normalize=True)
        cls.codegen = proj.analyses.Decompiler(cfg.functions[0], cfg=cfg).codegen

    def _render(self, from_bits: int, to_bits: int, value: int = 0x1234) -> str:
        conv = Expr.Convert(0, from_bits, to_bits, False, Expr.Const(0, value, from_bits))
        return self.codegen._handle(conv).c_repr()

    def test_truncation_to_unrepresentable_width_is_masked(self):
        # No C type is 5, 3 or 1 bits wide. A cast would round up to the next real type and keep
        # bits the conversion discards, so these have to be spelled as a mask instead.
        assert self._render(32, 5) == "4660 & 31"
        assert self._render(32, 3) == "4660 & 7"
        assert self._render(32, 1) == "4660 & 1"

    def test_truncation_to_representable_width_is_a_cast(self):
        assert self._render(32, 8) == "(char)4660"
        assert self._render(32, 16) == "(unsigned short)4660"

    def test_widening_is_always_a_cast(self):
        # Rounding up only loses information when truncating, so widening keeps casting even to a
        # width no C type has.
        assert self._render(1, 5, value=1) == "(char)1"
        assert self._render(8, 12, value=3) == "(unsigned short)3"
        assert self._render(32, 64, value=3) == "(unsigned long long)3"

    def test_narrow_arithmetic_shift_preserves_operand_width(self):
        value = Expr.Convert(0, 32, 8, True, Expr.Const(1, 127, 32))
        masked = Expr.BinaryOp(2, "And", (value, Expr.Const(3, 127, 8)), True, bits=8)
        incremented = Expr.BinaryOp(4, "Add", (masked, Expr.Const(5, 1, 8)), True, bits=8)
        shifted = Expr.BinaryOp(6, "Sar", (incremented, Expr.Const(7, 1, 8)), True, bits=8)

        assert self.codegen._handle(shifted).c_repr() == "(char)(((char)127 & 127) + 1) >> 1"

        char_alias = TypeRef("small_int", SimTypeChar(signed=True))
        aliased_value = CFakeVariable("value", char_alias, codegen=self.codegen)
        aliased_add = CBinaryOp(
            "Add", aliased_value, CConstant(1, char_alias, codegen=self.codegen), codegen=self.codegen
        )
        aliased_shift = CBinaryOp(
            "Sar", aliased_add, CConstant(1, SimTypeChar(), codegen=self.codegen), codegen=self.codegen
        )
        assert aliased_shift.c_repr() == "(char)(value + 1) >> 1"


if __name__ == "__main__":
    unittest.main()
