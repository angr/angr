#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import TestCase, main

from angr import claripy
from angr.claripy.vsa import mv_eval


def values_at(mv: claripy.ast.BV, offset: int, size: int) -> set[claripy.ast.BV]:
    values = mv_eval(mv.get_bytes(offset, size))
    assert values is not None
    return set(values)


class TestMultiValues(TestCase):
    def test_multivalues_one_slot_has_multiple_sized_bvs(self):
        mv = claripy.Concat(claripy.BVV(0, 32), claripy.BVV(1, 32), claripy.BVV(2, 32))
        mv = claripy.Concat(mv.get_bytes(0, 4), claripy.union(mv.get_bytes(4, 8), claripy.BVV(0x1338133813371337, 64)))

        assert len(mv) == 96
        assert values_at(mv, 0, 4) == {claripy.BVV(0, 32)}
        assert values_at(mv, 4, 4) == {claripy.BVV(1, 32), claripy.BVV(0x13381338, 32)}
        assert values_at(mv, 8, 4) == {claripy.BVV(2, 32), claripy.BVV(0x13371337, 32)}

        mv = claripy.Concat(
            mv.get_bytes(0, 5), claripy.union(mv.get_bytes(5, 1), claripy.BVV(0xCC, 8)), mv.get_bytes(6, 6)
        )
        assert len(mv) == 96
        assert values_at(mv, 5, 1) == {claripy.BVV(0xCC, 8), claripy.BVV(0x38, 8), claripy.BVV(0, 8)}
        assert values_at(mv, 6, 2) == {claripy.BVV(1, 16), claripy.BVV(0x1338, 16)}

    def test_multivalues_empty(self):
        mv = claripy.BVV(b"")
        assert mv_eval(mv) == (mv,)
        assert len(mv) == 0

    def test_multivalues_single_value(self):
        v = claripy.BVV(0x1338133813371337, 64)
        assert mv_eval(v) == (v,)
        assert len(v) == 64

        mv2 = claripy.union(v, v)
        assert mv_eval(mv2) == (v,)
        assert len(mv2) == 64

    def test_copy_construction_does_not_alias_the_source(self):
        src = claripy.Concat(claripy.BVV(0x11, 8), claripy.BVV(0x22, 8))
        copied = src

        copied = claripy.Concat(copied, claripy.BVV(0x33, 8))
        assert len(copied) == 24
        assert src is claripy.BVV(0x1122, 16)

    def test_concat_does_not_mutate_the_receiver(self):
        lhs = claripy.Concat(claripy.BVV(0x11, 8), claripy.BVV(0x22, 8))
        rhs = claripy.BVV(0x33, 8)

        result = lhs.concat(rhs)

        assert len(lhs) == 16
        assert len(result) == 24
        assert values_at(result, 2, 1) == {claripy.BVV(0x33, 8)}

    def test_concat_with_an_aliasing_operand(self):
        # RDA hands the same value to both operands of e.g. Iop_16HLto32(t, t), so concat must tolerate self is other.
        mv = claripy.Concat(claripy.BVV(0x11, 8), claripy.BVV(0x22, 8))

        result = mv.concat(mv)

        assert len(mv) == 16
        assert result is claripy.BVV(0x11221122, 32)

    def test_concat_with_a_copy_constructed_operand(self):
        lhs = claripy.Concat(claripy.BVV(0x11, 8), claripy.BVV(0x22, 8))
        rhs = claripy.Concat(claripy.BVV(0x11, 8), claripy.BVV(0x22, 8))

        result = lhs.concat(rhs)

        assert len(lhs) == 16
        assert len(rhs) == 16
        assert result is claripy.BVV(0x11221122, 32)


if __name__ == "__main__":
    main()
