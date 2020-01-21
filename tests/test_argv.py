import nose
import angr, claripy

import logging
l = logging.getLogger("angr_tests")

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_mips():
    proj = angr.Project(os.path.join(test_location, 'mips', 'argv_test'))
    r_addr = 0x400768

    s = proj.factory.entry_state(args = ['aaa', "Yan is a noob"], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic command line argument
    arg = claripy.BVS('arg_2', 50*8)
    s = proj.factory.entry_state(args = ['aaa', arg], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

def test_mipsel():
    proj = angr.Project(os.path.join(test_location, 'mipsel', 'argv_test'))
    r_addr = 0x400768
    s = proj.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

def test_i386():
    proj = angr.Project(os.path.join(test_location, 'i386', 'argv_test'))
    r_addr = 0x804845B
    s = proj.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

def test_amd64():
    proj = angr.Project(os.path.join(test_location, 'x86_64', 'argv_test'))
    r_addr = 0x400571
    s = proj.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

def test_arm():
    proj = angr.Project(os.path.join(test_location, 'armel', 'argv_test'))
    r_addr = 0x1048c

    s = proj.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

def test_ppc32():
    proj = angr.Project(os.path.join(test_location, 'ppc', 'argv_test'))
    r_addr = 0x10000498

    s = proj.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

if __name__ == "__main__":
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    test_ppc32()
