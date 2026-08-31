# pylint: disable=missing-class-docstring,no-self-use
"""The ``a == b  =>  hash(a) == hash(b)`` contract for AIL nodes.

Python requires that objects comparing equal hash equal. The Rust version of AIL broke this in two ways, both
regression-tested here:

* ``__eq__`` compared ``idx`` only at the root while the ``Hash`` impls fold ``idx`` in at every node, so any
  composite whose children had different ``idx`` compared equal and hashed apart.
* A handful of variants hashed a field the comparison never looked at. Those split two ways once examined:
  ``Const``'s ``NaN`` and signed-zero bit patterns were hash-side bugs (the values are equal, so they must hash
  the same), while ``Convert.rounding_mode``, ``BinaryOp.rounding_mode``, ``StringLiteral.bits`` and
  ``Struct.bits`` were comparison-side bugs (these fields were ignored in __eq__).
"""

from __future__ import annotations

import struct
import unittest

import angr.ailment.expression as eu
import angr.ailment.statement as su
from angr.ailment.manager import Manager
from angr.rustylib.ailment import (  # pylint:disable=import-error,no-name-in-module
    RoundingMode,
    VirtualVariableCategory,
)

ROOT = 0  # every pair below shares a root idx, so only the children vary


class _Kids:
    """A fresh set of sub-expressions, each with a distinct ``idx``."""

    def __init__(self, manager: Manager):
        n = manager.next_atom
        self.c1 = eu.Const(n(), 1, 32)
        self.c2 = eu.Const(n(), 2, 32)
        self.addr = eu.Const(n(), 0x1000, 64)
        self.reg = eu.Register(n(), 16, 32)
        self.vvar = eu.VirtualVariable(n(), 5, 32, VirtualVariableCategory.REGISTER, oident=16)
        self.dirty = eu.DirtyExpression(n(), "h", [eu.Const(n(), 1, 32)], bits=32)


# name -> build one instance at idx ``i`` from the sub-expressions ``k``.
EXPR_FACTORIES = {
    "Const": lambda i, k: eu.Const(i, 1, 32),
    "Tmp": lambda i, k: eu.Tmp(i, 5, 64),
    "Register": lambda i, k: eu.Register(i, 16, 64),
    "ComboRegister": lambda i, k: eu.ComboRegister(i, [k.reg, k.reg]),
    "VirtualVariable": lambda i, k: eu.VirtualVariable(i, 5, 64, VirtualVariableCategory.REGISTER, oident=16),
    "Phi": lambda i, k: eu.Phi(i, 32, [((0x400000, None), k.vvar)]),
    "UnaryOp": lambda i, k: eu.UnaryOp(i, "Neg", k.c1),
    "Convert": lambda i, k: eu.Convert(i, 32, 64, False, k.c1),
    "Reinterpret": lambda i, k: eu.Reinterpret(i, 32, "I", 32, "F", k.c1),
    "BinaryOp": lambda i, k: eu.BinaryOp(i, "Add", (k.c1, k.c2)),
    "Load": lambda i, k: eu.Load(i, k.addr, 8, "Iend_LE"),
    "Call": lambda i, k: eu.Call(i, k.c1, args=(k.c2,), bits=64),
    "ITE": lambda i, k: eu.ITE(i, k.c1, k.c1, k.c2),
    "Extract": lambda i, k: eu.Extract(i, 8, k.c1, k.c2, "Iend_LE"),
    "Insert": lambda i, k: eu.Insert(i, k.c1, k.c2, k.c1, "Iend_LE"),
    "StringLiteral": lambda i, k: eu.StringLiteral(i, "x", 8),
    "BasePointerOffset": lambda i, k: eu.BasePointerOffset(i, 64, "base", 0),
    "StackBaseOffset": lambda i, k: eu.StackBaseOffset(i, 64, -32),
    "DirtyExpression": lambda i, k: eu.DirtyExpression(i, "h", [k.c1], bits=32),
    "VEXCCallExpression": lambda i, k: eu.VEXCCallExpression(i, "h", (k.c1,), 32),
    "MultiStatementExpression": lambda i, k: eu.MultiStatementExpression(i, [], k.c1),
    "Struct": lambda i, k: eu.Struct(i, "F", {0: k.c1}, {"a": 0}, 32),
    "RustEnum": lambda i, k: eu.RustEnum(i, "E", [k.c1], 32),
    "Array": lambda i, k: eu.Array(i, [k.c1], 32),
    "Let": lambda i, k: eu.Let(i, [], k.c1),
    "Macro": lambda i, k: eu.Macro(i, "m"),
    "FunctionLikeMacro": lambda i, k: eu.FunctionLikeMacro(i, "m", [k.c1]),
}

STMT_FACTORIES = {
    "Assignment": lambda i, k: su.Assignment(i, k.reg, k.c1),
    "WeakAssignment": lambda i, k: su.WeakAssignment(i, k.reg, k.c1),
    "Label": lambda i, k: su.Label(i, "L"),
    "Store": lambda i, k: su.Store(i, k.addr, k.c1, 4, "Iend_LE"),
    "Jump": lambda i, k: su.Jump(i, k.addr),
    "ConditionalJump": lambda i, k: su.ConditionalJump(i, k.c1, k.addr, k.addr),
    "SideEffectStatement": lambda i, k: su.SideEffectStatement(i, k.c1),
    "Return": lambda i, k: su.Return(i, [k.c1]),
    "CAS": lambda i, k: su.CAS(i, k.addr, k.c1, None, k.c1, None, k.c1, None, "Iend_LE"),
    "DirtyStatement": lambda i, k: su.DirtyStatement(i, k.dirty),
}


def _assert_contract(case, a, b):
    """``a == b`` must imply ``hash(a) == hash(b)`` -- and the set agrees."""
    if a == b:
        assert hash(a) == hash(b), f"{case}: a == b but hash(a) != hash(b)"
        assert len({a, b}) == 1, f"{case}: a == b but the set kept both"


class TestHashEqContract(unittest.TestCase):
    """Per-variant sweeps plus the individual node-local regressions."""

    def _sweep(self, factories):
        manager = Manager()
        for name, build in factories.items():
            with self.subTest(variant=name):
                kids_a, kids_b = _Kids(manager), _Kids(manager)
                a = build(ROOT, kids_a)
                b = build(ROOT, kids_b)  # same shape, freshly-built children
                a_dup = build(ROOT, kids_a)  # same shape AND the same children

                # Positive control: without it a sweep where nothing ever
                # compares equal would pass while testing nothing.
                assert a == a_dup, f"{name}: identical build did not compare equal"
                assert hash(a) == hash(a_dup), f"{name}: identical build hashed differently"

                _assert_contract(name, a, b)
                _assert_contract(name, a, a_dup)

    def test_expression_variants(self):
        self._sweep(EXPR_FACTORIES)

    def test_statement_variants(self):
        self._sweep(STMT_FACTORIES)

    def test_nested_statement_over_expression(self):
        """The original report: a statement whose src subtree differs only in idx."""
        manager = Manager()
        n = manager.next_atom

        def src():
            return eu.BinaryOp(n(), "Add", [eu.Register(n(), 16, 32), eu.Const(n(), 1, 32)], False, bits=32)

        dst, sidx = eu.Register(n(), 24, 32), n()
        a = su.Assignment(sidx, dst, src())
        b = su.Assignment(sidx, dst, src())
        assert a.likes(b), "the two should still be structurally alike"
        _assert_contract("Assignment/nested", a, b)

    def test_const_nan(self):
        """``likes`` calls any NaN equal to any NaN, so they must hash alike."""
        n1 = struct.unpack("<d", struct.pack("<Q", 0x7FF8000000000001))[0]
        n2 = struct.unpack("<d", struct.pack("<Q", 0x7FF8000000000002))[0]
        a, b = eu.Const(ROOT, n1, 64), eu.Const(ROOT, n2, 64)
        assert a == b, "NaN Consts must stay equal (fixed-point loops rely on it)"
        _assert_contract("Const/NaN", a, b)

    def test_const_signed_zero(self):
        """IEEE says ``-0.0 == +0.0`` while the bit patterns differ."""
        a, b = eu.Const(ROOT, 0.0, 64), eu.Const(ROOT, -0.0, 64)
        assert a == b
        _assert_contract("Const/signed-zero", a, b)

    def test_convert_rounding_mode(self):
        """Rounding differently means computing a different value."""
        op = eu.Const(1, 5, 32)
        a = eu.Convert(ROOT, 32, 64, True, op, rounding_mode=RoundingMode.RM_NearestTiesEven)
        b = eu.Convert(ROOT, 32, 64, True, op, rounding_mode=RoundingMode.RM_TowardsZero)
        assert not a.likes(b) and not a.matches(b), "differing rounding modes are not alike"
        assert a != b
        _assert_contract("Convert/rounding_mode", a, b)

        same = eu.Convert(ROOT, 32, 64, True, op, rounding_mode=RoundingMode.RM_NearestTiesEven)
        assert a == same and hash(a) == hash(same)

        # a resolved mode and an absent one are also distinguishable
        none_rm = eu.Convert(ROOT, 32, 64, True, op)
        assert a != none_rm
        _assert_contract("Convert/rounding_mode-none", a, none_rm)

    def test_binop_rounding_mode(self):
        """``BinaryOp`` carries a rounding mode too, and it is significant."""
        x, y = eu.Const(1, 5, 32), eu.Const(2, 7, 32)
        a = eu.BinaryOp(
            ROOT, "Add", (x, y), False, bits=32, floating_point=True, rounding_mode=RoundingMode.RM_NearestTiesEven
        )
        b = eu.BinaryOp(
            ROOT, "Add", (x, y), False, bits=32, floating_point=True, rounding_mode=RoundingMode.RM_TowardsZero
        )
        assert not a.likes(b) and not a.matches(b), "differing rounding modes are not alike"
        assert a != b
        _assert_contract("BinaryOp/rounding_mode", a, b)

        same = eu.BinaryOp(
            ROOT, "Add", (x, y), False, bits=32, floating_point=True, rounding_mode=RoundingMode.RM_NearestTiesEven
        )
        assert a == same and hash(a) == hash(same)

    def test_rounding_mode_as_expression(self):
        """An unresolved rounding mode held in an expression still compares.

        VEX sometimes carries the mode in a tmp. That form recurses through
        ``cmp_ail``, so it observes the same idx-awareness as any subtree --
        and a resolved mode is never interchangeable with an unresolved one.
        """
        op = eu.Const(1, 5, 32)
        t1, t2 = eu.Tmp(2, 3, 32), eu.Tmp(2, 4, 32)
        a = eu.Convert(ROOT, 32, 64, True, op, rounding_mode=t1)
        b = eu.Convert(ROOT, 32, 64, True, op, rounding_mode=t2)
        assert a != b, "different tmps carry different modes"
        _assert_contract("Convert/rounding_mode-expr", a, b)

        same = eu.Convert(ROOT, 32, 64, True, op, rounding_mode=eu.Tmp(2, 3, 32))
        assert a == same and hash(a) == hash(same)

        resolved = eu.Convert(ROOT, 32, 64, True, op, rounding_mode=RoundingMode.RM_TowardsZero)
        assert a != resolved, "a tmp is not interchangeable with a resolved mode"
        _assert_contract("Convert/rounding_mode-mixed", a, resolved)

    def test_string_literal_bits(self):
        """``bits`` is significant for ``StringLiteral``, and is hashed."""
        a, b = eu.StringLiteral(ROOT, "abc", 32), eu.StringLiteral(ROOT, "abc", 64)
        assert not a.likes(b), "differing bits must not be alike"
        assert a != b
        _assert_contract("StringLiteral/bits", a, b)

        same = eu.StringLiteral(ROOT, "abc", 32)
        assert a == same and hash(a) == hash(same)

    def test_struct_bits(self):
        """``bits`` is significant for ``Struct``, and is hashed."""
        fields = {0: eu.Const(1, 7, 32)}
        a = eu.Struct(ROOT, "S", fields, {"a": 0}, 32)
        b = eu.Struct(ROOT, "S", fields, {"a": 0}, 64)
        assert not a.likes(b), "differing bits must not be alike"
        assert a != b
        _assert_contract("Struct/bits", a, b)

        same = eu.Struct(ROOT, "S", fields, {"a": 0}, 32)
        assert a == same and hash(a) == hash(same)


class TestMatchesPropagation(unittest.TestCase):
    """``matches`` must relax through *every* container, not just the
    variants that once had a hand-written override arm.

    ``Struct``, ``Array``, ``RustEnum``, ``Let`` and ``FunctionLikeMacro``
    have expression children but had no arm in the old override table, so
    they fell through to ``likes`` and the varid relaxation died at the
    container boundary.
    """

    CONTAINERS = {
        "Struct": lambda i, e: eu.Struct(i, "S", {0: e}, {"a": 0}, 32),
        "Array": lambda i, e: eu.Array(i, [e], 32),
        "RustEnum": lambda i, e: eu.RustEnum(i, "E", [e], 32),
        "Let": lambda i, e: eu.Let(i, [], e),
        "FunctionLikeMacro": lambda i, e: eu.FunctionLikeMacro(i, "m", [e]),
        # the variants that always had an arm -- regression guard
        "BinaryOp": lambda i, e: eu.BinaryOp(i, "Add", (e, e)),
        "UnaryOp": lambda i, e: eu.UnaryOp(i, "Neg", e),
    }

    def test_varid_relaxation_propagates(self):
        # the same source-level register read under two SSA numberings
        v1 = eu.VirtualVariable(0, 100, 32, VirtualVariableCategory.REGISTER, oident=16)
        v2 = eu.VirtualVariable(0, 200, 32, VirtualVariableCategory.REGISTER, oident=16)
        assert v1.matches(v2) and not v1.likes(v2), "bare vvar precondition"

        for name, wrap in self.CONTAINERS.items():
            with self.subTest(container=name):
                a, b = wrap(ROOT, v1), wrap(ROOT, v2)
                assert a.matches(b), f"{name}: matches did not propagate into the container"
                assert not a.likes(b), f"{name}: likes must still observe the varid"


if __name__ == "__main__":
    unittest.main()
