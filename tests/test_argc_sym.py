import nose
import angr, claripy

import logging
l = logging.getLogger("angr_tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_mips():
    arger_mips = angr.Project(test_location + "/mips/argc_symbol")
    r_addr = [0x400720, 0x40076c, 0x4007bc]

    sargc = claripy.BVS('argc', 32)
    s = arger_mips.factory.path(args = [claripy.BVS('arg_0', 40*8), claripy.BVS('arg_1', 40*8), claripy.BVS('arg_2', 40*8)], env ={"HOME": "/home/angr"}, argc=sargc)
    xpl = arger_mips.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(sargc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_mipsel():
    arger_mipsel = angr.Project(test_location + "/mipsel/argc_symbol")
    r_addr = [0x400720, 0x40076c, 0x4007bc]

    sargc = claripy.BVS('argc', 32)
    s = arger_mipsel.factory.path(args = [claripy.BVS('arg_0', 40*8), claripy.BVS('arg_1', 40*8), claripy.BVS('arg_2', 40*8)], env ={"HOME": "/home/angr"}, argc=sargc)
    xpl = arger_mipsel.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(sargc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_i386():
    arger_i386 = angr.Project(test_location + "/i386/argc_symbol")
    r_addr = [0x08048411, 0x08048437, 0x08048460]

    sargc = claripy.BVS('argc', 32)
    s = arger_i386.factory.path(args = [claripy.BVS('arg_0', 40*8), claripy.BVS('arg_1', 40*8), claripy.BVS('arg_2', 40*8)], env ={"HOME": "/home/angr"}, argc=sargc)
    xpl = arger_i386.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(sargc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_amd64():
    arger_amd64 = angr.Project(test_location + "/x86_64/argc_symbol", load_options={'auto_load_libs': False})
    r_addr = [0x40051B, 0x400540, 0x400569]

    sargc = claripy.BVS('argc', 64)
    s = arger_amd64.factory.path(args = [claripy.BVS('arg_0', 40*8), claripy.BVS('arg_1', 40*8), claripy.BVS('arg_2', 40*8)], env ={"HOME": "/home/angr"}, argc=sargc)
    xpl = arger_amd64.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(sargc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 800))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 800))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_arm():
    arger_arm = angr.Project(test_location + "/armel/argc_symbol")
    r_addr = [0x00010444, 0x00010478, 0x000104B0]

    sargc = claripy.BVS('argc', 32)
    s = arger_arm.factory.path(args = [claripy.BVS('arg_0', 40*8), claripy.BVS('arg_1', 40*8), claripy.BVS('arg_2', 40*8)], env ={"HOME": "/home/angr"}, argc=sargc)
    xpl = arger_arm.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(sargc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_ppc32():
    arger_ppc32 = angr.Project(test_location + "/ppc/argc_symbol")
    r_addr = [0x1000043C, 0x10000474, 0x100004B0]

    sargc = claripy.BVS('argc', 32)
    s = arger_ppc32.factory.path(args = [claripy.BVS('arg_0', 40*8), claripy.BVS('arg_1', 40*8), claripy.BVS('arg_2', 40*8)], env ={"HOME": "/home/angr"}, argc=sargc)
    xpl = arger_ppc32.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(sargc)
    conc = found.state.se.any_str(found.state.memory.load(found.state.registers.load('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

if __name__ == "__main__":
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    test_ppc32()
