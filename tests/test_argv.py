import nose
import angr, claripy

import logging
l = logging.getLogger("angr_tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_mips():
    arger_mips = angr.Project(test_location + "/mips/argv_test")
    r_addr = 0x400768

    s = arger_mips.factory.entry_state(args = ['aaa', "Yan is a noob"], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mips.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic command line argument
    s = arger_mips.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.se.any_str(found.memory.load(found.registers.load('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_mipsel():
    arger_mipsel = angr.Project(test_location + "/mipsel/argv_test")
    r_addr = 0x400768
    s = arger_mipsel.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mipsel.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_mipsel.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.se.any_str(found.memory.load(found.registers.load('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_i386():
    arger_i386 = angr.Project(test_location + "/i386/argv_test")
    r_addr = 0x804845B
    s = arger_i386.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_i386.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_i386.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.se.any_str(found.memory.load(found.registers.load('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_amd64():
    arger_amd64 = angr.Project(test_location + "/x86_64/argv_test")
    r_addr = 0x400571
    s = arger_amd64.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_amd64.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_amd64.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.se.any_str(found.memory.load(found.registers.load('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_arm():
    arger_arm = angr.Project(test_location + "/armel/argv_test")
    r_addr = 0x1048c

    s = arger_arm.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_arm.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_arm.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.se.any_str(found.memory.load(found.registers.load('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_ppc32():
    arger_ppc32 = angr.Project(test_location + "/ppc/argv_test")
    r_addr = 0x10000498

    s = arger_ppc32.factory.entry_state(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_ppc32.factory.entry_state(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_ppc32.factory.entry_state(args = ['aaa', claripy.BVS('arg_2', 50*8)], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.se.any_str(found.memory.load(found.registers.load('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

if __name__ == "__main__":
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    test_ppc32()
