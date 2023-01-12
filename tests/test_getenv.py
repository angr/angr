# Disable some pylint warnings: no-self-use, missing-docstring
# pylint: disable=R0201, C0111

import os
import logging

import unittest
import claripy
import angr

l = logging.getLogger("angr.tests.getenv")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestRunEcho(unittest.TestCase):
    flag = "this_is_a_string!"

    def test_run_getenv_with_env(self):
        env = {"PATH": "/home/angr/", "TEST_ENV1": "this_is_a_string!", "JAVA_HOME": "jdk-install-dir"}
        TEST_name = ["TEST_ENV1", "TEST_ENV2"]
        p = angr.Project(os.path.join(test_location, "x86_64", "test_getenv"))
        s = p.factory.entry_state(env=env)
        simgr = p.factory.simulation_manager(s)
        simgr.explore()

        assert len(simgr.deadended) == 1

        output_lines = simgr.deadended[0].posix.dumps(1).decode().splitlines(keepends=False)
        expect_output = (
            [f"# {k}={v}" for k, v in env.items()]
            + ["{k}: {v}".format(k=k, v=env.get(k, "__NULL__")) for k in TEST_name]
            + ["!! Bingo " + self.flag]
        )

        output_lines.sort()
        expect_output.sort()

        assert output_lines == expect_output

    def test_run_getenv_without_env(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "test_getenv"))
        s = p.factory.entry_state()
        simgr = p.factory.simulation_manager(s)
        simgr.explore()

        assert len(simgr.deadended) == 2

        bingo_count = 0
        for s in simgr.deadended:
            bingo_count += int(b"Bingo" in s.posix.dumps(1))

        assert bingo_count == 1

    def test_run_getenv_with_symbolic_env(self):
        flag = claripy.Concat(*[claripy.BVS("flag_%d" % i, 8) for i in range(30)])
        env = {"PATH": "/home/angr/", "TEST_ENV1": flag, "JAVA_HOME": "jdk-install-dir"}
        p = angr.Project(os.path.join(test_location, "x86_64", "test_getenv"))
        s = p.factory.entry_state(env=env)
        simgr = p.factory.simulation_manager(s)
        simgr.explore()

        assert len(simgr.deadended) == 2

        solved_flag = []
        for s in simgr.deadended:
            if b"Bingo" in s.posix.dumps(1):
                solved_flag.append(s.solver.eval(flag, cast_to=bytes).strip(b"\x00"))

        assert len(solved_flag) == 1
        assert solved_flag[0].decode() == self.flag


if __name__ == "__main__":
    unittest.main()
