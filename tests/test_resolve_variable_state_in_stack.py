import angr
from unittest import TestCase, main
import os
from cle.backends.elf.variable_type import *

TESTS_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join('..', '..', 'binaries')
)

def step_until(simgr, until, step=100):
    for i in range(step):
        simgr.step(selector_func = lambda s:
                   False if s.solver.eval(s._ip) == until else True)

class TestResolveVariableInStackStateFromName(TestCase):
    def setUp(self):
        self.p = angr.Project(
            os.path.join(TESTS_BASE, 'tests', 'x86_64', 'various_variables')
            , load_debug_info = True
        )
        self.p.kb.nvariables.load_from_dwarf()
        self.simgr = self.p.factory.simgr()

    def test_sum_in_global(self):
        addr = self.p.loader.find_symbol("sum_in_global").rebased_addr
        step_until(self.simgr, addr)
        self.simgr.step()
        self.simgr.step()
        s = self.simgr.active[0]
        result = []
        for i in range(9):
            result.append(s.nvariables["global_var"].mem.concrete)
            self.simgr.step()
            s = self.simgr.active[0]
        ref = [7, 8, 10, 13, 17, 22, 28, 35, 43]
        self.assertEqual(result, ref)

    def test_sum_in_local(self):
        addr = self.p.loader.find_symbol("sum_in_local").rebased_addr
        step_until(self.simgr, addr)
        self.simgr.step()
        s = self.simgr.active[0]
        local_var = s.nvariables["local_var"].mem.concrete
        ref = 0
        self.assertEqual(local_var, ref)

if __name__ == '__main__':
    main()

