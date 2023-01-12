import os
import unittest

import angr

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

find = {"veritesting_a": {"x86_64": 0x40066A}}

criteria = {"veritesting_a": lambda input_found: input_found.count(b"B") == 10}


class TestRun(unittest.TestCase):
    def _run_stochastic(self, binary, arch):
        proj = angr.Project(os.path.join(location, arch, binary), auto_load_libs=False)
        simgr = proj.factory.simulation_manager()
        start_state = simgr.active[0]
        technique = angr.exploration_techniques.StochasticSearch(start_state)
        simgr.use_technique(technique)

        def found(simgr):
            return simgr.active[0].addr == find[binary][arch]

        simgr.run(until=found)
        assert simgr.active[0].addr == find[binary][arch]

        input_found = simgr.active[0].posix.dumps(0)
        assert criteria[binary](input_found)

    def test_stochastic(self):
        self._run_stochastic("veritesting_a", "x86_64")


if __name__ == "__main__":
    unittest.main()
