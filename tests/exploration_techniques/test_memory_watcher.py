#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
import psutil

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestMemoryWatcher(unittest.TestCase):
    def test_memory_watcher(self):
        binary = os.path.join(test_location, "x86_64", "veritesting_a")
        proj = angr.Project(binary, auto_load_libs=False)
        simgr = proj.factory.simulation_manager()

        memory_watcher = angr.exploration_techniques.MemoryWatcher()
        simgr.use_technique(memory_watcher)

        # Initially build some paths
        while len(simgr.active) < 32 and simgr.active != []:
            simgr.step()

        # Something else went wrong..
        assert simgr.active != []

        # Set fake that memory watcher believes we're too low on memory
        memory_watcher.min_memory = psutil.virtual_memory().total

        previous_active = len(simgr.active)

        # Step once to move things over
        simgr.step()

        assert simgr.active == []
        assert len(getattr(simgr, memory_watcher.memory_stash)) == previous_active


if __name__ == "__main__":
    unittest.main()
