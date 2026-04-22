# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations
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


class TestIRegister(unittest.TestCase):
    """Unit tests for IRegister expression type."""

    def _make_ireg(self, ix_value, bits=64, base=904, bias=0, n_elems=8, shift=3):
        """Create an IRegister with a Const reg_offset."""
        ix = ailment.expression.Const(1, None, ix_value, 32)
        return ailment.expression.IRegister(
            2, None, ix, bits, array_base=base, array_bias=bias, array_nElems=n_elems, array_shift=shift
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
        tmp = ailment.expression.Tmp(1, None, 5, 32)
        ireg = ailment.expression.IRegister(2, None, tmp, 64, array_base=904, array_nElems=8, array_shift=3)
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
        old_ix = ailment.expression.Const(1, None, 5, 32)
        ireg = ailment.expression.IRegister(2, None, old_ix, 64, array_base=904, array_nElems=8, array_shift=3)
        new_ix = ailment.expression.Const(3, None, 0xFFFFFFFF, 32)
        replaced, result = ireg.replace(old_ix, new_ix)
        assert replaced
        assert result.reg_offset is new_ix
        assert result.array_base == 904

    def test_replace_no_match(self):
        ireg = self._make_ireg(0)
        other = ailment.expression.Const(99, None, 42, 32)
        new = ailment.expression.Const(100, None, 99, 32)
        replaced, result = ireg.replace(other, new)
        assert not replaced
        assert result is ireg

    def test_replace_self(self):
        ireg = self._make_ireg(0)
        new = ailment.expression.Const(99, None, 42, 32)
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
        inner = ailment.expression.Const(None, None, 42, 32)
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
        inner = ailment.expression.Const(None, None, 42, 32)
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
        inner = ailment.expression.Const(None, None, 42, 32)
        conv = ailment.expression.Convert(None, 32, 64, False, inner)
        assert conv.from_type == ailment.expression.Convert.TYPE_INT
        assert conv.to_type == ailment.expression.Convert.TYPE_INT


class TestBinaryOpFloatingPoint(unittest.TestCase):
    """Tests for floating_point flag on BinaryOp expressions."""

    def test_binaryop_floating_point_flag(self):
        a = ailment.expression.Const(None, None, 42, 64)
        b = ailment.expression.Const(None, None, 43, 64)
        op = ailment.expression.BinaryOp(None, "Fadd", [a, b], False, floating_point=True)
        assert op.floating_point is True
        assert op.tags.get("_floating_point") is True

    def test_binaryop_floating_point_preserved_in_tags(self):
        a = ailment.expression.Const(None, None, 42, 64)
        b = ailment.expression.Const(None, None, 43, 64)
        op = ailment.expression.BinaryOp(None, "Fadd", [a, b], False, floating_point=True)
        op_copy = op.copy()
        assert op_copy.floating_point is True

    def test_binaryop_not_floating_point_by_default(self):
        a = ailment.expression.Const(None, None, 42, 64)
        b = ailment.expression.Const(None, None, 43, 64)
        op = ailment.expression.BinaryOp(None, "Add", [a, b], False)
        assert op.floating_point is False


if __name__ == "__main__":
    unittest.main()
