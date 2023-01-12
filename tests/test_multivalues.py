# pylint:disable=missing-class-docstring,no-self-use
from unittest import TestCase, main

import claripy
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


if __name__ == "__main__":
    main()
