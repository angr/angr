#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""The opt-in function-address change log: FunctionIndex, PyFunctionIndex, RecoveryFunctions and FunctionManager."""

from __future__ import annotations

import os
import unittest

import angr
from angr.knowledge_plugins.functions.function_index import FunctionIndex, PyFunctionIndex
from angr.knowledge_plugins.functions.recovery import RecoveryFunctionManager
from angr.rustylib.recovery_functions import RecoveryFunctions
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestIndexChanges(unittest.TestCase):
    def _indexes(self):
        return [FunctionIndex(), PyFunctionIndex()]

    def test_net_changes(self):
        for idx in self._indexes():
            with self.subTest(type(idx).__name__):
                idx.add(0x10)
                idx.add(0x50)
                c = idx.changes_cursor()
                assert idx.changes_since(c) == ([], [], c)
                idx.add(0x30)
                idx.add(0x20)
                idx.add(0x20)  # no-op
                idx.discard(0x50)
                idx.discard(0x60)  # no-op
                idx.add(0x40)
                idx.discard(0x40)  # cancels
                added, removed, c2 = idx.changes_since(c)
                assert (added, removed) == ([0x20, 0x30], [0x50])
                # cursors stay valid; a later cursor sees only later changes
                idx.discard(0x30)
                assert idx.changes_since(c)[:2] == ([0x20], [0x50])
                assert idx.changes_since(c2)[:2] == ([], [0x30])

    def test_remove_then_readd(self):
        for idx in self._indexes():
            with self.subTest(type(idx).__name__):
                idx.add(0x10)
                c = idx.changes_cursor()
                idx.discard(0x10)
                idx.add(0x10)
                assert idx.changes_since(c)[:2] == ([], [])
                idx.discard(0x10)
                assert idx.changes_since(c)[:2] == ([], [0x10])

    def test_epoch_reset(self):
        for idx in self._indexes():
            with self.subTest(type(idx).__name__):
                idx.add(0x10)
                c = idx.changes_cursor()
                idx.add(0x20)
                cp = idx.copy()
                assert cp.addrs() == [0x10, 0x20]
                assert cp.changes_since(c) is None
                # cache resets keep the addresses and the log
                idx.clear_caches()
                assert idx.changes_since(c)[:2] == ([0x20], [])
                idx.clear_addrs()
                assert idx.changes_since(c) is None
                c2 = idx.changes_cursor()
                assert c2[0] != c[0]
                idx.add(0x30)
                assert idx.changes_since(c2)[:2] == ([0x30], [])

    def test_recovery_store(self):
        store = RecoveryFunctions()
        g = store.create(0x10)
        c = store.changes_cursor()
        store.create(0x20)
        store.import_record(0x30, g, "f", True, [], None, False, False, False, False, None, {})
        store.remove(0x10)
        store.remove(0x20)
        assert store.changes_since(c)[:2] == ([0x30], [0x10])
        assert RecoveryFunctions().changes_since(c) is None


class TestFunctionManagerChanges(unittest.TestCase):
    def test_function_manager(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        for cache_limit in (None, 2):
            with self.subTest(cache_limit=cache_limit):
                kb = angr.KnowledgeBase(proj)
                fm = kb.functions
                if cache_limit is not None:
                    fm.cache_limit = cache_limit
                fm.function(addr=0x400580, create=True)
                c = fm.changes_cursor()
                for addr in (0x400600, 0x400640, 0x400680, 0x4006C0):
                    fm.function(addr=addr, create=True)
                del fm[0x400580]
                del fm[0x400640]
                added, removed, c2 = fm.changes_since(c)
                assert (added, removed) == ([0x400600, 0x400680, 0x4006C0], [0x400580])
                assert fm.changes_since(c2)[:2] == ([], [])
                assert fm.copy().changes_since(c2) is None
                fm.clear()
                assert fm.changes_since(c2) is None


class TestCFGFastChanges(unittest.TestCase):
    def test_cfgfast_scan_changes(self):
        """Cursors taken mid-scan on the RecoveryFunctionManager yield exactly the net address changes."""
        # armel fauxware removes functions during the scan
        proj = angr.Project(os.path.join(bin_location, "tests", "armel", "fauxware"), auto_load_libs=False)
        cursors: dict = {}
        state: dict = {"fm": None, "n": 0}
        orig_create, orig_delitem = RecoveryFunctionManager._create, RecoveryFunctionManager.__delitem__

        def take(fm, key):
            if key not in cursors:
                state["fm"] = fm
                cursors[key] = (fm.changes_cursor(), set(fm))

        def create(self, addr, syscall=None):
            view = orig_create(self, addr, syscall=syscall)
            state["n"] += 1
            if state["n"] == 5:
                take(self, "create")
            return view

        def delitem(self, k):
            take(self, "delete")
            orig_delitem(self, k)

        RecoveryFunctionManager._create = create
        RecoveryFunctionManager.__delitem__ = delitem
        try:
            cfg = proj.analyses.CFGFast(normalize=True)
        finally:
            RecoveryFunctionManager._create, RecoveryFunctionManager.__delitem__ = orig_create, orig_delitem
        rfm: RecoveryFunctionManager = state["fm"]
        after = set(rfm)
        assert set(cursors) == {"create", "delete"}
        for cursor, before in cursors.values():
            added, removed, _ = rfm.changes_since(cursor)
            assert added == sorted(after - before)
            assert removed == sorted(before - after)
        assert rfm.changes_since(cursors["delete"][0])[1]
        # make_functions builds a new manager: the cursor does not carry over
        assert cfg.kb.functions is not rfm
        assert cfg.kb.functions.changes_since(cursors["create"][0]) is None


if __name__ == "__main__":
    unittest.main()
