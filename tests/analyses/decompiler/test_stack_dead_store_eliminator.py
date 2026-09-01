#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.analyses.decompiler.stack_dead_store_eliminator import StackAddr, StackDeadStoreEliminator


class TestCanonicalFrameAddr(unittest.TestCase):
    """The rule that picks one frame address when the frame pointer merges to several."""

    @staticmethod
    def _addr(chain, offset):
        return StackAddr("sp", tuple(("add", v) for v in chain), offset)

    def test_prefers_the_least_derived_value(self):
        # The frame pointer as established, versus the same pointer after a path took an
        # adjustment: the shorter derivation is the canonical one.
        established = self._addr((-216, 8, -16, -136), -360)
        adjusted = self._addr((-216, 8, -16, -136, 152, -16, 8, -16, -136), -368)
        for addrs in ((established, adjusted), (adjusted, established)):
            assert StackDeadStoreEliminator._canonical_frame_addr(addrs) is established

    def test_ties_go_to_the_highest_offset(self):
        low = self._addr((-16,), -16)
        high = self._addr((-8,), -8)
        assert StackDeadStoreEliminator._canonical_frame_addr((low, high)) is high

    def test_a_known_offset_beats_an_opaque_one(self):
        opaque = StackAddr("sp", (("and", -16),), None)
        known = StackAddr("sp", (("add", -8),), -8)
        assert StackDeadStoreEliminator._canonical_frame_addr((opaque, known)) is known

    def test_choice_does_not_depend_on_input_order(self):
        a = self._addr((-8, 16), 8)
        b = self._addr((-8, 24), 16)
        c = self._addr((-8, 24, 8), 24)
        assert (
            StackDeadStoreEliminator._canonical_frame_addr((a, b, c))
            is StackDeadStoreEliminator._canonical_frame_addr((c, b, a))
        )


if __name__ == "__main__":
    unittest.main()
