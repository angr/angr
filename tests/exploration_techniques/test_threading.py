from __future__ import annotations

import os
import unittest

import angr
from angr.exploration_techniques import Threading

from tests.common import bin_location


class TestThreading(unittest.TestCase):
    def test_threading_basic(self):
        # Load the fauxware binary
        binary_path = os.path.join(bin_location, "tests", "x86_64", "fauxware")
        project = angr.Project(binary_path)

        # Create initial state
        state = project.factory.entry_state()
        simgr = project.factory.simulation_manager(state)

        # Add threading technique
        threading = Threading(threads=4)
        simgr.use_technique(threading)

        # Step a few times to test threading
        simgr.run(n=5)

        # Basic checks
        self.assertTrue(len(simgr.active) > 0)
        self.assertFalse(simgr.errored)


if __name__ == "__main__":
    unittest.main()
