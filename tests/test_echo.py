# pylint: disable=missing-class-docstring,disable=no-self-use
import logging
import os
import unittest

import angr

l = logging.getLogger("angr.tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

target_arches = {
    # 'i386',
    'x86_64',
    # 'ppc',
    # 'armel',
    # 'mips',
}


class TestEcho(unittest.TestCase):
    def run_echo_haha(self, arch):
        # auto_load_libs can't be disabled as the test fails
        p = angr.Project(os.path.join(test_location, arch, 'echo'), use_sim_procedures=False)
        s = p.factory.full_init_state(mode='symbolic_approximating', args=['echo', 'haha'],
                                      add_options={angr.options.STRICT_PAGE_ACCESS})
        pg = p.factory.simulation_manager(s)
        pg.run(until=lambda lpg: len(lpg.active) != 1)

        assert len(pg.deadended) == 1
        assert len(pg.active) == 0
        # Need to dump by path because the program closes stdout
        assert pg.deadended[0].posix.stdout.concretize() == [b'haha\n']

    def test_echo_haha(self):
        for arch in target_arches:
            yield self.run_echo_haha, arch


if __name__ == "__main__":
    unittest.main()
