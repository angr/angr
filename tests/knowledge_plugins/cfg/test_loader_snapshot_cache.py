#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""Project.loader_snapshot(): one LoaderSnapshot per loader state, shared by CFGModel's data-reference tidying."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest
from unittest import mock

import angr
from angr.analyses.cfg import loader_snapshot
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestLoaderSnapshotCache(unittest.TestCase):
    def _project(self):
        return angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)

    def test_tidy_data_references_reuses_snapshot(self):
        proj = self._project()
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        addrs = list(cfg.model.memory_data)[:4]
        assert addrs
        with mock.patch.object(
            loader_snapshot, "build_loader_snapshot", wraps=loader_snapshot.build_loader_snapshot
        ) as build:
            cfg.model.tidy_data_references(memory_data_addrs=addrs)
            cfg.model.tidy_data_references(memory_data_addrs=addrs)
        assert build.call_count <= 1
        assert cfg.model._take_loader_snapshot() is proj.loader_snapshot()

    def test_rebuilt_on_new_symbol(self):
        proj = self._project()
        snap = proj.loader_snapshot()
        assert proj.loader_snapshot() is snap
        proj.loader.extern_object.make_extern("angr_test_snapshot_symbol")
        assert proj.loader_snapshot() is not snap

    def test_rebuilt_on_new_backer(self):
        proj = self._project()
        snap = proj.loader_snapshot()
        addr = (proj.loader.max_addr + 0x10000) & ~0xFFF
        proj.loader.memory.add_backer(addr, bytearray(0x100))
        new = proj.loader_snapshot()
        assert new is not snap
        assert new.load_byte(addr) == 0

    def test_pickle(self):
        proj = self._project()
        proj.loader_snapshot()
        restored = pickle.loads(pickle.dumps(proj))
        assert restored._loader_snapshot_cache is None
        assert restored.loader_snapshot() is restored.loader_snapshot()


if __name__ == "__main__":
    unittest.main()
