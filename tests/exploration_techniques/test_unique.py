#!/usr/bin/env python3
__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")

find = {"veritesting_a": {"x86_64": 0x40066A}}

criteria = {"veritesting_a": lambda input_found: input_found.count(b"B") == 10}


class TestRunUnique(unittest.TestCase):
    def _run_unique(self, binary, arch):
        proj = angr.Project(os.path.join(test_location, arch, binary), auto_load_libs=False)
        simgr = proj.factory.simulation_manager()
        technique = angr.exploration_techniques.UniqueSearch()
        simgr.use_technique(technique)

        def found(simgr):
            return simgr.active[0].addr == find[binary][arch]

        simgr.run(until=found)
        assert simgr.active[0].addr == find[binary][arch]

        input_found = simgr.active[0].posix.dumps(0)
        assert criteria[binary](input_found)

    def test_unique(self):
        self._run_unique("veritesting_a", "x86_64")


if __name__ == "__main__":
    unittest.main()
