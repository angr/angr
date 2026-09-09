#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import TestCase, main

from angr import claripy
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues


class TestMultiValues(TestCase):
    def test_multivalues_one_slot_has_multiple_sized_bvs(self):
        mv = MultiValues(offset_to_values={0: {claripy.BVV(0, 32)}, 4: {claripy.BVV(1, 32)}, 8: {claripy.BVV(2, 32)}})
        mv.add_value(4, claripy.BVV(0x1338133813371337, 64))

        assert len(mv._values) == 3
        assert len(mv._values[4]) == 2
        assert mv._values[4] == {claripy.BVV(1, 32), claripy.BVV(0x13381338, 32)}
        assert mv._values[8] == {claripy.BVV(2, 32), claripy.BVV(0x13371337, 32)}

        mv.add_value(5, claripy.BVV(0xCC, 8))
        assert len(mv._values) == 5  # 0, 4, 5, 6, 8
        assert mv._values[5] == {claripy.BVV(0xCC, 8), claripy.BVV(0x38, 8), claripy.BVV(0, 8)}
        assert mv._values[6] == {claripy.BVV(1, 16), claripy.BVV(0x1338, 16)}

    def test_multivalues_empty(self):
        mv = MultiValues()
        assert mv._single_value is None
        assert mv._values == {}
        assert len(mv) == 0

    def test_multivalues_single_value(self):
        v = claripy.BVV(0x1338133813371337, 64)
        mv = MultiValues(v)
        assert mv._single_value is not None
        assert v.concrete_value == mv._single_value.concrete_value
        assert len(mv) == 64

        mv2 = MultiValues(mv)
        assert mv2._single_value is not None
        assert v.concrete_value == mv2._single_value.concrete_value
        assert len(mv2) == 64

    def test_copy_construction_does_not_alias_the_source(self):
        src = MultiValues(offset_to_values={0: {claripy.BVV(0x11, 8)}, 1: {claripy.BVV(0x22, 8)}})
        copied = MultiValues(src)

        assert copied._values is not src._values
        assert copied._values[0] is not src._values[0]

        copied.add_value(2, claripy.BVV(0x33, 8))
        assert src.keys() == {0, 1}

    def test_concat_does_not_mutate_the_receiver(self):
        lhs = MultiValues(offset_to_values={0: {claripy.BVV(0x11, 8)}, 1: {claripy.BVV(0x22, 8)}})
        rhs = MultiValues(claripy.BVV(0x33, 8))

        result = lhs.concat(rhs)

        assert lhs.keys() == {0, 1}
        assert result.keys() == {0, 1, 2}
        assert result._values[2] == {claripy.BVV(0x33, 8)}

    def test_concat_with_an_aliasing_operand(self):
        # RDA hands the same MultiValues object to both operands of e.g. Iop_16HLto32(t, t), so concat must
        # tolerate self is other. It used to raise "dictionary changed size during iteration".
        mv = MultiValues(offset_to_values={0: {claripy.BVV(0x11, 8)}, 1: {claripy.BVV(0x22, 8)}})

        result = mv.concat(mv)

        assert mv.keys() == {0, 1}
        assert result.keys() == {0, 1, 2, 3}

    def test_concat_with_a_copy_constructed_operand(self):
        lhs = MultiValues(offset_to_values={0: {claripy.BVV(0x11, 8)}, 1: {claripy.BVV(0x22, 8)}})
        rhs = MultiValues(lhs)

        result = lhs.concat(rhs)

        assert lhs.keys() == {0, 1}
        assert rhs.keys() == {0, 1}
        assert result.keys() == {0, 1, 2, 3}


if __name__ == "__main__":
    main()
