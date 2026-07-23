#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use

"""Test that CFGFast resolves delay-load import calls to the named import.

The fixture ``delay_import.exe`` delay-loads ``user32.dll!MessageBoxA``. CLE binds the delay-import slot to an extern
stub (see cle PE backend ``_handle_delay_imports``), so the ``call``/``jmp`` through the delay IAT should resolve in
the CFG to the ``MessageBoxA`` SimProcedure rather than being left unresolved or pointing at the delay-load thunk.
"""

from __future__ import annotations

import os
import unittest

import angr
from tests.common import bin_location

TEST_BINARY = os.path.join(bin_location, "tests", "x86_64", "windows", "delay_import.exe")


class TestCFGDelayImport(unittest.TestCase):
    def test_delay_import_resolved_after_cfg(self):
        proj = angr.Project(TEST_BINARY, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)

        # the delay-imported symbol is bound to a hooked extern stub
        sym = proj.loader.find_symbol("MessageBoxA")
        self.assertIsNotNone(sym)
        self.assertTrue(proj.is_hooked(sym.rebased_addr))

        # ... and recovered as a function during CFG recovery
        self.assertTrue(proj.kb.functions.contains_addr(sym.rebased_addr))
        func = proj.kb.functions.get_by_addr(sym.rebased_addr)
        self.assertEqual(func.name, "MessageBoxA")
        self.assertTrue(func.is_simprocedure)

        # the delay-load call site resolved to it: MessageBoxA has at least one caller in the call graph, and its CFG
        # node has predecessors (the indirect call through the delay IAT was resolved, not dropped as unresolvable)
        callgraph = proj.kb.functions.callgraph
        self.assertIn(sym.rebased_addr, callgraph)
        self.assertGreater(callgraph.in_degree(sym.rebased_addr), 0)

        node = cfg.model.get_any_node(sym.rebased_addr)
        self.assertIsNotNone(node)
        self.assertGreater(len(cfg.model.get_predecessors(node)), 0)


if __name__ == "__main__":
    unittest.main()
