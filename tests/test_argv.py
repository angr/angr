import logging
import os
import unittest

import angr
import claripy

l = logging.getLogger("angr_tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestArgv(unittest.TestCase):
    def test_mips(self):
        proj = angr.Project(os.path.join(test_location, "mips", "argv_test"), auto_load_libs=False)
        r_addr = 0x400768

        s = proj.factory.entry_state(args=["aaa", "Yan is a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "Yan is not a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

        # symbolic command line argument
        arg = claripy.BVS("arg_2", 50 * 8)
        s = proj.factory.entry_state(args=["aaa", arg], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        found = xpl.found[0]
        conc = found.solver.eval(found.memory.load(found.registers.load("sp"), 400), cast_to=bytes)

        assert b"Yan is a noob" in conc

    def test_mipsel(self):
        proj = angr.Project(os.path.join(test_location, "mipsel", "argv_test"), auto_load_libs=False)
        r_addr = 0x400768
        s = proj.factory.entry_state(args=["aaa", "Yan is a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "Yan is not a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

        # symbolic args
        s = proj.factory.entry_state(args=["aaa", claripy.BVS("arg_2", 50 * 8)], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        found = xpl.found[0]
        conc = found.solver.eval(found.memory.load(found.registers.load("sp"), 400), cast_to=bytes)

        assert b"Yan is a noob" in conc

    def test_i386(self):
        proj = angr.Project(os.path.join(test_location, "i386", "argv_test"), auto_load_libs=False)
        r_addr = 0x804845B
        s = proj.factory.entry_state(args=["aaa", "Yan is a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "Yan is not a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

        # symbolic args
        s = proj.factory.entry_state(args=["aaa", claripy.BVS("arg_2", 50 * 8)], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        found = xpl.found[0]
        conc = found.solver.eval(found.memory.load(found.registers.load("sp"), 400), cast_to=bytes)

        assert b"Yan is a noob" in conc

    def test_amd64(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "argv_test"), auto_load_libs=False)
        r_addr = 0x400571
        s = proj.factory.entry_state(args=["aaa", "Yan is a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "Yan is not a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

        # symbolic args
        s = proj.factory.entry_state(args=["aaa", claripy.BVS("arg_2", 50 * 8)], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        found = xpl.found[0]
        conc = found.solver.eval(found.memory.load(found.registers.load("sp"), 400), cast_to=bytes)

        assert b"Yan is a noob" in conc

    def test_arm(self):
        proj = angr.Project(os.path.join(test_location, "armel", "argv_test"), auto_load_libs=False)
        r_addr = 0x1048C

        s = proj.factory.entry_state(args=["aaa", "Yan is a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "Yan is not a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

        # symbolic args
        s = proj.factory.entry_state(args=["aaa", claripy.BVS("arg_2", 50 * 8)], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        found = xpl.found[0]
        conc = found.solver.eval(found.memory.load(found.registers.load("sp"), 400), cast_to=bytes)

        assert b"Yan is a noob" in conc

    def test_ppc32(self):
        proj = angr.Project(os.path.join(test_location, "ppc", "argv_test"), auto_load_libs=False)
        r_addr = 0x10000498

        s = proj.factory.entry_state(args=["aaa", "Yan is a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "Yan is not a noob"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

        # symbolic args
        s = proj.factory.entry_state(args=["aaa", claripy.BVS("arg_2", 50 * 8)], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        found = xpl.found[0]
        conc = found.solver.eval(found.memory.load(found.registers.load("sp"), 400), cast_to=bytes)

        assert b"Yan is a noob" in conc


if __name__ == "__main__":
    unittest.main()
