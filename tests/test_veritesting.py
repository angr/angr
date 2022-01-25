import os
import unittest
import logging

import angr


l = logging.getLogger('angr_tests.veritesting')

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

addresses_veritesting_a = {
    'x86_64': 0x400674
}

addresses_veritesting_b = {
    'x86_64': 0x4006af
}

class TestVeritesting(unittest.TestCase):
    def _run_veritesting_a(self,arch):
        # TODO: Added timeout control, since a failed state merging will result in running for a long time

        #logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

        proj = angr.Project(os.path.join(location, arch, "veritesting_a"),
                            load_options={'auto_load_libs': False},
                            use_sim_procedures=True
                            )
        ex = proj.factory.simulation_manager(veritesting=True)
        ex.explore(find=addresses_veritesting_a[arch])
        assert len(ex.found) != 0
        # Make sure the input makes sense
        for f in ex.found:
            input_str = f.plugins['posix'].dumps(0)
            assert input_str.count(b'B') == 10

    def _run_veritesting_b(self,arch):
        #logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

        proj = angr.Project(os.path.join(location, arch, "veritesting_b"),
                            load_options={'auto_load_libs': False},
                            use_sim_procedures=True
                            )
        ex = proj.factory.simulation_manager()
        ex.use_technique(angr.exploration_techniques.Veritesting(enable_function_inlining=True))
        ex.explore(find=addresses_veritesting_b[arch])
        assert len(ex.found) != 0
        # Make sure the input makes sense
        for f in ex.found:
            input_str = f.plugins['posix'].dumps(0)
            assert input_str.count(b'B') == 35

    def test_veritesting_a(self):
        # This is the most basic test
        self._run_veritesting_a('x86_64')

    def test_veritesting_b(self):
        # Advanced stuff - it tests for the ability to inline simple functions
        # as well as simple syscalls like read/write
        self._run_veritesting_b('x86_64')

if __name__ == "__main__":
    unittest.main()
