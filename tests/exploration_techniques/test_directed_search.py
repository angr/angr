#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.exploration_techniques import DirectedSearch
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# A block of main in brancher that the Director tests also explore to.
TARGET = 0x4005B4


class TestDirectedSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "brancher"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast()

    def _simgr(self, technique=None):
        simgr = self.proj.factory.simulation_manager(self.proj.factory.entry_state())
        if technique is not None:
            simgr.use_technique(technique)
        return simgr

    def test_rejects_bad_arguments(self):
        with self.assertRaises(ValueError):
            DirectedSearch(self.cfg, TARGET, beam_width=0)
        with self.assertRaises(ValueError):
            DirectedSearch(self.cfg, 0xDEADBEEF)

    def test_distance(self):
        ds = DirectedSearch(self.cfg.model, TARGET)
        assert ds.distance(TARGET) == 0
        # A mid-block address has its block's distance.
        assert ds.distance(TARGET + 1) == 0
        entry = self.proj.entry
        assert 0 < ds.distance(entry) < float("inf")
        assert ds.distance(0xDEADBEEF) == float("inf")

    def test_active_is_always_the_closest(self):
        ds = DirectedSearch(self.cfg, TARGET, beam_width=2)
        simgr = self._simgr(ds)
        saw_deferred = False
        for _ in range(30):
            simgr.step()
            if not simgr.active:
                break
            deferred = simgr.stashes[ds.deferred_stash]
            saw_deferred |= bool(deferred)
            worst_active = max(ds.distance(s.addr) for s in simgr.active)
            assert all(ds.distance(s.addr) >= worst_active for s in deferred)
            dists = [ds.distance(s.addr) for s in deferred]
            assert dists == sorted(dists)
        assert saw_deferred

    def test_closer_deferred_state_comes_back(self):
        ds = DirectedSearch(self.cfg, TARGET)
        simgr = self._simgr(ds)
        near = self.proj.factory.blank_state(addr=TARGET)
        simgr.stashes[ds.deferred_stash].append(near)
        simgr.step()
        # The entry state's successor has a distance above 0, so the deferred state at the target takes the one slot.
        assert simgr.active == [near]
        assert ds.distance(simgr.stashes[ds.deferred_stash][0].addr) > 0

    def test_reaches_the_target_with_less_work_than_bfs(self):
        def explore(simgr):
            # The number of active states summed over the steps it takes to find the target
            active_states = [0]

            def count(sm):
                active_states[0] += len(sm.active)
                return False

            simgr.explore(find=TARGET, num_find=1, until=count, n=200)
            assert simgr.found and simgr.found[0].addr == TARGET
            return active_states[0]

        assert explore(self._simgr(DirectedSearch(self.cfg, TARGET))) < explore(self._simgr())


if __name__ == "__main__":
    unittest.main()
