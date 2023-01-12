import logging
import os
import unittest

import angr
import claripy

l = logging.getLogger("angr_tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestArgcSym(unittest.TestCase):
    def _verify_results(self, pg, sargc, length=400):
        argcs = pg.mp_found.solver.eval(sargc)
        strs = pg.mp_found.solver.eval(pg.mp_found.memory.load(pg.mp_found.regs.sp, length), cast_to=bytes)

        for a, s in zip(argcs.mp_items, strs.mp_items):
            assert a in (0, 1, 2)
            assert b"Good man" in s if a == 1 else b"Very Good man" if a == 2 else True

    def test_mips(self):
        arger_mips = angr.Project(os.path.join(test_location, "mips", "argc_symbol"), auto_load_libs=False)
        r_addr = [0x400720, 0x40076C, 0x4007BC]

        sargc = claripy.BVS("argc", 32)
        s = arger_mips.factory.entry_state(
            args=[claripy.BVS("arg_0", 40 * 8), claripy.BVS("arg_1", 40 * 8), claripy.BVS("arg_2", 40 * 8)],
            env={"HOME": "/home/angr"},
            argc=sargc,
        )
        pg = arger_mips.factory.simulation_manager(s).explore(find=r_addr, num_find=100)
        self._verify_results(pg, sargc)

    def test_mipsel(self):
        arger_mipsel = angr.Project(os.path.join(test_location, "mipsel", "argc_symbol"), auto_load_libs=False)
        r_addr = [0x400720, 0x40076C, 0x4007BC]

        sargc = claripy.BVS("argc", 32)
        s = arger_mipsel.factory.entry_state(
            args=[claripy.BVS("arg_0", 40 * 8), claripy.BVS("arg_1", 40 * 8), claripy.BVS("arg_2", 40 * 8)],
            env={"HOME": "/home/angr"},
            argc=sargc,
        )
        pg = arger_mipsel.factory.simulation_manager(s).explore(find=r_addr, num_find=100)
        self._verify_results(pg, sargc)

    def test_i386(self):
        arger_i386 = angr.Project(os.path.join(test_location, "i386", "argc_symbol"), auto_load_libs=False)
        r_addr = [0x08048411, 0x08048437, 0x08048460]

        sargc = claripy.BVS("argc", 32)
        s = arger_i386.factory.entry_state(
            args=[claripy.BVS("arg_0", 40 * 8), claripy.BVS("arg_1", 40 * 8), claripy.BVS("arg_2", 40 * 8)],
            env={"HOME": "/home/angr"},
            argc=sargc,
        )
        pg = arger_i386.factory.simulation_manager(s).explore(find=r_addr, num_find=100)
        self._verify_results(pg, sargc)

    def test_amd64(self):
        arger_amd64 = angr.Project(
            os.path.join(test_location, "x86_64", "argc_symbol"), load_options={"auto_load_libs": False}
        )
        r_addr = [0x40051B, 0x400540, 0x400569]

        sargc = claripy.BVS("argc", 64)
        s = arger_amd64.factory.entry_state(
            args=[claripy.BVS("arg_0", 40 * 8), claripy.BVS("arg_1", 40 * 8), claripy.BVS("arg_2", 40 * 8)],
            env={"HOME": "/home/angr"},
            argc=sargc,
        )
        pg = arger_amd64.factory.simulation_manager(s).explore(find=r_addr, num_find=100)
        self._verify_results(pg, sargc, length=800)

    def test_arm(self):
        arger_arm = angr.Project(os.path.join(test_location, "armel", "argc_symbol"), auto_load_libs=False)
        r_addr = [0x00010444, 0x00010478, 0x000104B0]

        sargc = claripy.BVS("argc", 32)
        s = arger_arm.factory.entry_state(
            args=[claripy.BVS("arg_0", 40 * 8), claripy.BVS("arg_1", 40 * 8), claripy.BVS("arg_2", 40 * 8)],
            env={"HOME": "/home/angr"},
            argc=sargc,
        )
        pg = arger_arm.factory.simulation_manager(s).explore(find=r_addr, num_find=100)
        self._verify_results(pg, sargc)

    def test_ppc32(self):
        arger_ppc32 = angr.Project(os.path.join(test_location, "ppc", "argc_symbol"), auto_load_libs=False)
        r_addr = [0x1000043C, 0x10000474, 0x100004B0]

        sargc = claripy.BVS("argc", 32)
        s = arger_ppc32.factory.entry_state(
            args=[claripy.BVS("arg_0", 40 * 8), claripy.BVS("arg_1", 40 * 8), claripy.BVS("arg_2", 40 * 8)],
            env={"HOME": "/home/angr"},
            argc=sargc,
        )
        pg = arger_ppc32.factory.simulation_manager(s).explore(find=r_addr, num_find=100)
        self._verify_results(pg, sargc)


if __name__ == "__main__":
    unittest.main()
