import os
import math

from unittest import TestCase, main

import angr

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


class TestDwarfVariables(TestCase):
    """
    Test dwarf variables import and resolution of these variables
    """

    def setUp(self):
        self.p = angr.Project(os.path.join(TESTS_BASE, "tests", "x86_64", "various_variables"), load_debug_info=True)
        self.p.kb.dvars.load_from_dwarf()
        simgr = self.p.factory.simgr()
        main_addr = self.p.loader.find_symbol("main").rebased_addr
        simgr.explore(find=main_addr)
        self.s = simgr.found[0]
        self.addr2line = self.p.loader.main_object.addr_to_line

    # tests for global variables

    def test_resolve_a(self):
        a = self.s.dvars["a"]
        computed_result = []
        for i in range(9):
            computed_result.append(a.array(i).mem.concrete)
        expected_result = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        self.assertEqual(computed_result, expected_result, 'global variable "a" array values is computed wrong')

    def test_resolve_pointer(self):
        pointer = self.s.dvars["pointer"]
        computed_result = pointer.deref.mem.concrete
        expected_result = 0
        self.assertEqual(
            computed_result, expected_result, 'global variable "pointer" dereferences value is computed wrong'
        )

    def test_resolve_pointer2(self):
        pointer2 = self.s.dvars["pointer2"]
        computed_result = pointer2.deref.mem.concrete
        expected_result = 1
        self.assertEqual(
            computed_result, expected_result, 'global variable "pointer2" dereferences value is computed wrong'
        )

    def test_resolve_global_var(self):
        global_var = self.s.dvars["global_var"]
        computed_result = global_var.mem.concrete
        expected_result = 7
        self.assertEqual(computed_result, expected_result, 'global variable "global_var" value is computed wrong')

    def test_resolve_extern_var(self):
        extern_var = self.s.dvars["extern_var"]
        computed_result = extern_var.mem.concrete
        expected_result = 42
        self.assertEqual(computed_result, expected_result, 'global variable "extern_var" value is computed wrong')

    def test_resolve_global_struct(self):
        global_struct = self.s.dvars["global_struct"]

        computed_struct_array = []
        a = global_struct.member("struct_array")
        for i in range(3):
            computed_struct_array.append(a.array(i).mem.concrete)

        computed_result = [
            global_struct.member("struct_fun").mem.concrete,
            global_struct.member("struct_int").mem.concrete,
            global_struct.member("struct_ll").mem.concrete,
            global_struct.member("struct_char").mem.concrete,
            global_struct.member("struct_strref").string.concrete,
            global_struct.member("struct_pointer").mem.concrete,
            computed_struct_array,
            # struct_float is tested below,
            # struct_double is tested below,
            global_struct.member("struct_my_type").mem.concrete,
        ]

        expected_result = [
            self.p.loader.find_symbol("variable_scopes").rebased_addr,
            42,
            256,
            b"a",
            b"hello",
            self.s.dvars["dummy"].addr,
            [9, 8, 7],
            # 1.141,
            # 1.141,
            16,
        ]

        self.assertEqual(
            computed_result, expected_result, 'global variable "global_struct" members value is computed wrong'
        )

        struct_float = global_struct.member("struct_float").mem.concrete
        struct_double = global_struct.member("struct_double").mem.concrete
        self.assertTrue(
            math.isclose(struct_float, 1.141, rel_tol=1e-7) and math.isclose(struct_double, 1.141, rel_tol=1e-7)
        )

    # tests for local variables

    def test_sum_in_global(self):
        simgr = self.p.factory.simgr()
        addr = self.p.loader.find_symbol("sum_in_global").rebased_addr
        simgr.explore(find=addr)
        simgr.move(from_stash="found", to_stash="active")
        simgr.step()
        simgr.step()
        s = simgr.active[0]
        result = []
        for _ in range(9):
            result.append(s.dvars["global_var"].mem.concrete)
            simgr.step()
            s = simgr.active[0]
        ref = [7, 8, 10, 13, 17, 22, 28, 35, 43]
        self.assertEqual(result, ref)

    def test_sum_in_local(self):
        simgr = self.p.factory.simgr()
        addr = self.p.loader.find_symbol("sum_in_local").rebased_addr
        simgr.explore(find=addr)
        simgr.move(from_stash="found", to_stash="active")
        simgr.step()
        s = simgr.active[0]
        local_var = s.dvars["local_var"].mem.concrete
        ref = 0
        self.assertEqual(local_var, ref)

    def test_variable_scopes(self):
        simgr = self.p.factory.simgr()
        filename = "/home/lukas/Software/angr-dev/binaries/tests_src/various_variables.c"
        lines_strings = [
            (78, b"He"),
            (80, b"llo "),
            # (84, b"Wor"),  # FIXME fails
            (88, b"ld!\n"),
        ]
        for line, expected_string in lines_strings:
            addr = {addr for addr in self.addr2line if self.addr2line[addr] == (filename, line)}.pop()
            simgr.explore(find=addr)
            s = simgr.found[0]
            computed_string = s.dvars["string"].string.concrete
            self.assertEqual(expected_string, computed_string)
            simgr.move(from_stash="found", to_stash="active")

    def test_sum_in_static(self):
        simgr = self.p.factory.simgr()
        filename = "/home/lukas/Software/angr-dev/binaries/tests_src/various_variables.c"
        line = 47
        addr = {addr for addr in self.addr2line if self.addr2line[addr] == (filename, line)}.pop()
        simgr.explore(find=addr)
        s = simgr.found[0]
        computed_value = s.dvars["static_var"].mem.concrete
        self.assertEqual(computed_value, 0)

    def test_local_in_loop(self):
        simgr = self.p.factory.simgr()
        filename = "/home/lukas/Software/angr-dev/binaries/tests_src/various_variables.c"
        line = 55
        addr = {addr for addr in self.addr2line if self.addr2line[addr] == (filename, line)}.pop()
        simgr.explore(find=addr)
        s = simgr.found[0]
        computed_value = s.dvars["local_in_loop"].mem.concrete
        self.assertEqual(computed_value, 9)

    def test_local_in_if(self):
        simgr = self.p.factory.simgr()
        filename = "/home/lukas/Software/angr-dev/binaries/tests_src/various_variables.c"
        line = 68
        addr = {addr for addr in self.addr2line if self.addr2line[addr] == (filename, line)}.pop()
        simgr.explore(find=addr)
        s = simgr.found[0]
        computed_value = s.dvars["local_in_if"].mem.concrete
        self.assertEqual(computed_value, 52)

    def test_resolve_local_struct(self):
        simgr = self.p.factory.simgr()
        filename = "/home/lukas/Software/angr-dev/binaries/tests_src/various_variables.c"
        line = 144
        addr = {addr for addr in self.addr2line if self.addr2line[addr] == (filename, line)}.pop()
        simgr.explore(find=addr)
        s = simgr.found[0]
        local_struct = s.dvars["local_struct"]

        computed_struct_array = []
        a = local_struct.member("struct_array")
        for i in range(3):
            computed_struct_array.append(a.array(i).mem.concrete)

        computed_result = [
            local_struct.member("struct_fun").mem.concrete,
            local_struct.member("struct_int").mem.concrete,
            local_struct.member("struct_ll").mem.concrete,
            local_struct.member("struct_char").mem.concrete,
            local_struct.member("struct_strref").string.concrete,
            local_struct.member("struct_pointer").mem.concrete,
            computed_struct_array,
            # struct_float is tested below,
            # struct_double is tested below,
            local_struct.member("struct_my_type").mem.concrete,
        ]

        expected_result = [
            self.p.loader.find_symbol("variable_scopes").rebased_addr,
            42,
            256,
            b"a",
            b"hello",
            s.dvars["local_pointer"].mem.concrete,
            [9, 8, 7],
            # 1.141,
            # 1.141,
            16,
        ]

        self.assertEqual(
            computed_result, expected_result, 'local variable "local_struct" members value is computed wrong'
        )

        struct_float = local_struct.member("struct_float").mem.concrete
        struct_double = local_struct.member("struct_double").mem.concrete
        self.assertTrue(
            math.isclose(struct_float, 1.141, rel_tol=1e-7) and math.isclose(struct_double, 1.141, rel_tol=1e-7)
        )


if __name__ == "__main__":
    main()
