from __future__ import annotations

import unittest
import networkx

import angr
from angr import claripy
from angr.analyses.symbolizer.symbolizer import Symbolizer, PropagatorState
from angr.storage.memory_mixins import DefaultListPagesMemory

class Node:
    # identity-hashed, so two nodes may share a block id
    def __init__(self, block_id):
        self.block_id = block_id


class TestSymbolizerSparsePrevInput(unittest.TestCase):
    """Previous inputs are kept only where a later visit compares against them."""

    def _state(self):
        plugins = angr.SimState._presets["default"]._default_plugins
        old = plugins["sym_memory"]
        plugins["sym_memory"] = DefaultListPagesMemory
        try:
            proj = angr.load_shellcode(b"\xc3", arch="AMD64")
            return proj.factory.blank_state(addr=0)
        finally:
            plugins["sym_memory"] = old

    def _sym(self):
        # start -> a -> head <-> body, head -> b; b2 (start -> b2) shares b's block id
        start, a, head, body, b, b2 = (Node(i) for i in ("start", "a", "head", "body", "b", "b"))
        g = networkx.DiGraph([(start, a), (a, head), (head, body), (body, head), (head, b), (start, b2)])
        sym = Symbolizer.__new__(Symbolizer)
        sym._graph = g
        sym._prev_input_states = {}
        sym._input_taken = set()
        sym._once_only = set()
        sym._start_node = start
        sym._shared_block_ids = {"b"}
        return sym, start, a, head, body, b

    def test_keeps_only_readable_inputs(self):
        sym, start, a, head, body, b = self._sym()
        st = self._state()
        st.memory.store(0x1000, claripy.BVV(1, 32))
        for n in (start, a, head, body, b):
            sym._keep_input(n, [st])
        self.assertEqual(sym._input_taken, {"start", "a", "head", "body", "b"})
        # a and body have one predecessor: nothing compares against them without a merged state
        self.assertEqual(set(sym._prev_input_states), {"start", "head", "b"})

        same = st.copy()
        top = st.copy()
        top.memory.store(0x1000, PropagatorState.top(32))
        self.assertFalse(sym._input_changed(head, same))
        self.assertTrue(sym._input_changed(head, top))
        # no pages kept: re-run
        self.assertTrue(sym._input_changed(body, same))

    def test_once_only_takes_nothing(self):
        sym, start, a, head, body, b = self._sym()
        sym._once_only = {head}
        sym._keep_input(head, [self._state()])
        self.assertEqual(sym._input_taken, set())
        self.assertEqual(sym._prev_input_states, {})


if __name__ == "__main__":
    unittest.main()
