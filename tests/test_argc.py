import logging
import os
import unittest

import angr

l = logging.getLogger("angr_tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestArgc(unittest.TestCase):
    def test_mips(self):
        proj = angr.Project(os.path.join(test_location, "mips", "argc_decide"), auto_load_libs=False)
        r_addr = 0x4006F4

        s = proj.factory.entry_state(args=["aaa"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "bbb"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

    def test_mipsel(self):
        proj = angr.Project(os.path.join(test_location, "mipsel", "argc_decide"), auto_load_libs=False)
        r_addr = 0x400708
        s = proj.factory.entry_state(args=["aaa", "bbb"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

    def test_i386(self):
        proj = angr.Project(os.path.join(test_location, "i386", "argc_decide"), auto_load_libs=False)
        r_addr = 0x80483D4
        s = proj.factory.entry_state(args=["aaa"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "bbb"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

    def test_amd64(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "argc_decide"), auto_load_libs=False)
        r_addr = 0x4004C7
        s = proj.factory.entry_state(args=["aaa"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "bbb"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

    def test_arm(self):
        proj = angr.Project(os.path.join(test_location, "armel", "argc_decide"), auto_load_libs=False)
        r_addr = 0x1040C

        s = proj.factory.entry_state(args=["aaa"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "bbb"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0

    def test_ppc32(self):
        proj = angr.Project(os.path.join(test_location, "ppc", "argc_decide"), auto_load_libs=False)
        r_addr = 0x10000404

        s = proj.factory.entry_state(args=["aaa"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 1

        s = proj.factory.entry_state(args=["aaa", "bbb"], env={"HOME": "/home/angr"})
        xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

        assert len(xpl.found) == 0


if __name__ == "__main__":
    unittest.main()
