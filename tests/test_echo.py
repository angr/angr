# pylint: disable=missing-class-docstring,disable=no-self-use
import logging
import os
import unittest

import angr

l = logging.getLogger("angr.tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestEcho(unittest.TestCase):
    def _run_echo_haha(self, arch):
        # auto_load_libs can't be disabled as the test fails
        p = angr.Project(os.path.join(test_location, arch, "echo"), use_sim_procedures=False)
        s = p.factory.full_init_state(
            mode="symbolic_approximating", args=["echo", "haha"], add_options={angr.options.STRICT_PAGE_ACCESS}
        )
        pg = p.factory.simulation_manager(s)
        pg.run(until=lambda lpg: len(lpg.active) != 1)

        assert len(pg.deadended) == 1
        assert len(pg.active) == 0
        # Need to dump by path because the program closes stdout
        assert pg.deadended[0].posix.stdout.concretize() == [b"haha\n"]

    def test_echo_haha(self):
        self._run_echo_haha("x86_64")


if __name__ == "__main__":
    unittest.main()
