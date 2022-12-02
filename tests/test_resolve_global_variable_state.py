import angr
from unittest import TestCase, main
import os
from cle.backends.elf.variable_type import *
import math

TESTS_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join('..', '..', 'binaries')
)

def step_until(simgr, until, step=100):
    for i in range(step):
        simgr.step(selector_func = lambda s:
                   False if s.solver.eval(s._ip) == until else True)

class TestResolveGlobalVariableInStateFromName(TestCase):
    def setUp(self):
        p = angr.Project(
            os.path.join(TESTS_BASE, 'tests', 'x86_64', 'various_variables')
            , load_debug_info = True
        )
        p.kb.nvariables.load_from_dwarf()
        simgr = p.factory.simgr()
        main_addr = p.loader.find_symbol("main").rebased_addr
        simgr.explore(find = main_addr)
        self.s = simgr.found[0]

    def test_resolve_a(self):
        a = self.s.nvariables["a"]
        computed_result = []
        for i in range(9):
            computed_result.append(a.array(i).mem.concrete)
        expected_result = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        self.assertEqual(computed_result, expected_result
                         , "global variable \"a\" array values is computed wrong")

    def test_resolve_pointer(self):
        pointer = self.s.nvariables["pointer"]
        computed_result = pointer.deref.mem.concrete
        expected_result = 0
        self.assertEqual(computed_result, expected_result,
                         "global variable \"pointer\" dereferences value is computed wrong")

    def test_resolve_pointer2(self):
        pointer2 = self.s.nvariables["pointer2"]
        computed_result = pointer2.deref.mem.concrete
        expected_result = 1
        self.assertEqual(computed_result, expected_result,
                         "global variable \"pointer2\" dereferences value is computed wrong")

    def test_resolve_global_var(self):
        global_var = self.s.nvariables["global_var"]
        computed_result = global_var.mem.concrete
        expected_result = 7
        self.assertEqual(computed_result, expected_result,
                         "global variable \"global_var\" value is computed wrong")

    def test_resolve_extern_var(self):
        extern_var = self.s.nvariables["extern_var"]
        computed_result = extern_var.mem.concrete
        expected_result = 42
        self.assertEqual(computed_result, expected_result,
                         "global variable \"extern_var\" value is computed wrong")

    def test_resolve_global_struct(self):
        global_struct = self.s.nvariables["global_struct"]
        computed_result = []
        # TODO add struct_fun

        struct_int = global_struct.member("struct_int").mem.concrete
        computed_result.append(struct_int)
        struct_ll = global_struct.member("struct_ll").mem.concrete
        computed_result.append(struct_ll)
        struct_char = global_struct.member("struct_char").mem.concrete
        computed_result.append(struct_char)
        # TODO add struct_strref

        # TODO add correct behavior of struct_pointer
        #struct_pointer = global_struct.member("struct_pointer").mem.concrete

        struct_array = []
        for i in range(3):
            array_val = global_struct.member("struct_array").array(i).mem.concrete
            struct_array.append(array_val)
        computed_result.append(struct_array)
        expected_result = [42, 256, b'a', [9, 8, 7]]
        self.assertEqual(computed_result, expected_result,
                         "global variable \"global_struct\" members value is computed wrong")
        struct_float = global_struct.member("struct_float").mem.concrete
        struct_double = global_struct.member("struct_double").mem.concrete
        self.assertTrue(math.isclose(struct_float, 1.141, rel_tol = 1e-7)
                        and math.isclose(struct_double, 1.141, rel_tol = 1e-7))






