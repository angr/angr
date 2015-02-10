#!/usr/bin/env python
# pylint: disable=no-member

import nose
import logging
l = logging.getLogger("angr_tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
arger_amd64 = None
arger_i386 = None
arger_ppc32 = None
arger_arm = None
arger_mipsel = None
arger_mips = None

def setup_ppc32():
    global arger_ppc32
    arger_ppc32 = angr.Project(test_location + "/blob/ppc/argc_symbol")

def setup_mips():
    global arger_mips
    arger_mips = angr.Project(test_location + "/blob/mips/argc_symbol")

def setup_mipsel():
    global arger_mipsel
    arger_mipsel = angr.Project(test_location + "/blob/mipsel/argc_symbol")

def setup_amd64():
    global arger_amd64
    arger_amd64 = angr.Project(test_location + "/blob/x86_64/argc_symbol")

def setup_i386():
    global arger_i386
    arger_i386 = angr.Project(test_location + "/blob/i386/argc_symbol")

def setup_arm():
    global arger_arm
    arger_arm = angr.Project(test_location + "/blob/armel/argc_symbol")

def setup_module():
    setup_i386()
    setup_amd64()
    setup_mipsel()
    setup_mips()
    setup_arm()
    setup_ppc32()

def test_mips():
    r_addr = [0x400720, 0x40076c, 0x4007bc]

    s = arger_mips.path_generator.entry_point(args = [angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40)], env ={"HOME": "/home/angr"}, sargc=True)
    xpl = arger_mips.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(found.state['posix'].argc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_mipsel():
    r_addr = [0x400720, 0x40076c, 0x4007bc]

    s = arger_mipsel.path_generator.entry_point(args = [angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40)], env ={"HOME": "/home/angr"}, sargc=True)
    xpl = arger_mipsel.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(found.state['posix'].argc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_i386():
    r_addr = [0x08048411, 0x08048437, 0x08048460]

    s = arger_i386.path_generator.entry_point(args = [angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40)], env ={"HOME": "/home/angr"}, sargc=True)
    xpl = arger_i386.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(found.state['posix'].argc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_amd64():
    r_addr = [0x40051B, 0x400540, 0x400569]

    s = arger_amd64.path_generator.entry_point(args = [angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40)], env ={"HOME": "/home/angr"}, sargc=True)
    xpl = arger_amd64.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(found.state['posix'].argc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 800))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 800))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_arm():
    r_addr = [0x00010444, 0x00010478, 0x000104B0]

    s = arger_arm.path_generator.entry_point(args = [angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40)], env ={"HOME": "/home/angr"}, sargc=True)
    xpl = arger_arm.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(found.state['posix'].argc)
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

def test_ppc32():
    r_addr = [0x1000043C, 0x10000474, 0x100004B0]

    s = arger_ppc32.path_generator.entry_point(args = [angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40), angr.StringSpec(sym_length=40)], env ={"HOME": "/home/angr"}, sargc=True)
    xpl = arger_ppc32.surveyors.Explorer(find=r_addr, num_find=100, start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 3)

    found = xpl.found[0]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals(argc, 0)

    found = xpl.found[1]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Good man" in conc, True)
    nose.tools.assert_equals(argc, 1)

    found = xpl.found[2]
    argc = found.state.se.any_int(found.state['posix'].argc)
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))
    nose.tools.assert_equals("Very Good man" in conc, True)
    nose.tools.assert_equals(argc, 2)

if __name__ == "__main__":
    setup_module()
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    test_ppc32()
