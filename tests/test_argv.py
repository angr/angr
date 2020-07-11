import nose
import angr, claripy

import logging
l = logging.getLogger("angr_tests")

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test():
    proj1 = angr.Project(os.path.join(test_location, 'mips', 'argv_test'))
    r_addr = 0x400768

    s = proj1.factory.entry_state(args = ['aaa', "Yan is a noob"], env ={"HOME": "/home/angr"})
    xpl = proj1.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj1.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj1.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # Does this matter?
    s = proj1.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj1.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)
    
    proj2 = angr.Project(os.path.join(test_location, 'mipsel', 'argv_test'))
    r_addr = 0x400768
    s = proj2.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj2.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj2.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj2.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj2.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj2.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

    proj3 = angr.Project(os.path.join(test_location, 'i386', 'argv_test'))
    r_addr = 0x804845B
    s = proj3.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj3.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj3.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj3.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj3.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj3.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

    proj4 = angr.Project(os.path.join(test_location, 'x86_64', 'argv_test'))
    r_addr = 0x400571
    s = proj4.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj4.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj4.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj4.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj4.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj4.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

    proj5 = angr.Project(os.path.join(test_location, 'armel', 'argv_test'))
    r_addr = 0x1048c

    s = proj5.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj5.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj5.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj5.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj5.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj5.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

    proj6 = angr.Project(os.path.join(test_location, 'ppc', 'argv_test'))
    r_addr = 0x10000498

    s = proj6.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = proj6.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 1)

    s = proj6.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = proj6.factory.simulation_manager(s).explore(find=r_addr)

    nose.tools.assert_equal(len(xpl.found), 0)

    # symbolic args
    s = proj6.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = proj6.factory.simulation_manager(s).explore(find=r_addr)

    found = xpl.found[0]
    conc = found.solver.eval(found.memory.load(found.registers.load('sp'), 400), cast_to=bytes)

    nose.tools.assert_equal(b"Yan is a noob" in conc, True)

if __name__ == "__main__":
    test()
