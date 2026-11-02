from __future__ import annotations

import unittest

import angr
from angr import claripy
from angr.analyses.symbolizer.symbolizer import PropagatorState, Symbolizer, _InputPages
from angr.storage.memory_mixins import DefaultListPagesMemory


class TestSymbolizerInputPages(unittest.TestCase):
    """The symbolizer keeps only the pages of a node's previous input; comparing against them must give the same
    answer as comparing against the whole state."""

    def _state(self):
        # the VM deobfuscation scripts run on list pages
        plugins = angr.SimState._presets["default"]._default_plugins
        old = plugins["sym_memory"]
        plugins["sym_memory"] = DefaultListPagesMemory
        try:
            proj = angr.load_shellcode(b"\xc3", arch="AMD64")
            return proj.factory.blank_state(addr=0)
        finally:
            plugins["sym_memory"] = old

    def test_same_verdicts_as_the_whole_state(self):
        sym = Symbolizer.__new__(Symbolizer)
        base = self._state()
        base.memory.store(0x1000, claripy.BVV(1, 32))
        base.regs.rbx = 5

        def compare_both(prev, new):
            whole = sym.compare_concrete_states(new, prev)
            pages = sym.compare_concrete_states(new, _InputPages(prev))
            self.assertEqual(whole, pages)
            return pages

        same = base.copy()
        self.assertFalse(compare_both(base, same))

        # a different non-TOP value counts as unchanged, a TOP value does not
        other_value = base.copy()
        other_value.memory.store(0x1000, claripy.BVV(2, 32))
        self.assertFalse(compare_both(base, other_value))
        top = base.copy()
        top.memory.store(0x1000, PropagatorState.top(32))
        self.assertTrue(compare_both(base, top))
        top_reg = base.copy()
        top_reg.regs.rbx = PropagatorState.top(64)
        self.assertTrue(compare_both(base, top_reg))

        # a page the previous input did not have
        new_page = base.copy()
        new_page.memory.store(0x80000, claripy.BVV(3, 32))
        self.assertTrue(compare_both(base, new_page))


if __name__ == "__main__":
    unittest.main()
