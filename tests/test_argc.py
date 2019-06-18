import nose
import angr

import logging
l = logging.getLogger("angr_tests")

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_mips():
    proj = angr.Project(os.path.join(test_location, 'mips', 'argc_decide'))
    r_addr = 0x4006f4

    s = proj.factory.entry_state(args = ['aaa'], env = {"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

def test_mipsel():
    proj = angr.Project(os.path.join(test_location, 'mipsel', 'argc_decide'))
    r_addr = 0x400708
    s = proj.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

def test_i386():
    proj = angr.Project(os.path.join(test_location, 'i386', 'argc_decide'))
    r_addr = 0x80483d4
    s = proj.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

def test_amd64():
    proj = angr.Project(os.path.join(test_location, 'x86_64', 'argc_decide'))
    r_addr = 0x4004c7
    s = proj.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

def test_arm():
    proj = angr.Project(os.path.join(test_location, 'armel', 'argc_decide'))
    r_addr = 0x1040c

    s = proj.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

def test_ppc32():
    proj = angr.Project(os.path.join(test_location, 'ppc', 'argc_decide'))
    r_addr = 0x10000404

    s = proj.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

if __name__ == "__main__":
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    test_ppc32()
