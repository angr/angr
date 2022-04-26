import os
import logging

import unittest

import angr

l = logging.getLogger("angr.tests.getenv")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

class TestRunEcho(unittest.TestCase): #pylint: disable=missing-class-docstring
    flag = "!! Bingo this_is_a_string!"

    def _run_getenv_with_env(self,arch):
        env =  { "PATH":"/home/angr/", "TEST_ENV1":"this_is_a_string!", "JAVA_HOME":"jdk-install-dir"}
        TEST_name = [ "TEST_ENV1" , "TEST_ENV2" ]
        p = angr.Project(os.path.join(test_location, arch, 'test_getenv'))
        s = p.factory.entry_state(env = env)
        simgr = p.factory.simulation_manager(s)
        simgr.explore()

        assert len(simgr.deadended) == 1

        output_lines = simgr.deadended[0].posix.dumps(1).decode().splitlines(keepends=False)
        expect_output = ["# {k}={v}".format(k=k,v=v) for k,v in env.items()] + \
            [ "{k}: {v}".format(k=k, v=env.get(k,"__NULL__"))  for k in TEST_name ] + \
                [self.flag]

        output_lines.sort()
        expect_output.sort()

        assert output_lines == expect_output

    def _run_getenv_without_env(self,arch):
        p = angr.Project(os.path.join(test_location, arch, 'test_getenv'))
        s = p.factory.entry_state()
        simgr = p.factory.simulation_manager(s)
        simgr.explore()

        assert len(simgr.deadended) == 2

        bingo_count = 0
        for s in simgr.deadended:
            bingo_count += int(self.flag in s.posix.dumps(1).decode())

        assert bingo_count == 1

    def test_run_x86_64(self):
        self._run_getenv_with_env('x86_64')
        self._run_getenv_without_env('x86_64')

if __name__ == "__main__":
    unittest.main()
