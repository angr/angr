#!/usr/bin/env python

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
    arger_ppc32 = angr.Project(test_location + "/blob/ppc/argv_test")

def setup_mips():
    global arger_mips
    arger_mips = angr.Project(test_location + "/blob/mips/argv_test")

def setup_mipsel():
    global arger_mipsel
    arger_mipsel = angr.Project(test_location + "/blob/mipsel/argv_test")

def setup_amd64():
    global arger_amd64
    arger_amd64 = angr.Project(test_location + "/blob/x86_64/argv_test")

def setup_i386():
    global arger_i386
    arger_i386 = angr.Project(test_location + "/blob/i386/argv_test")

def setup_arm():
    global arger_arm
    arger_arm = angr.Project(test_location + "/blob/armel/argv_test")

def setup_module():
    setup_i386()
    setup_amd64()
    setup_mipsel()
    setup_mips()
    setup_arm()
    setup_ppc32()

def test_mips():
    r_addr = 0x400768

    s = arger_mips.path_generator.entry_point(args = ['aaa', "Yan is a noob"], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mips.path_generator.entry_point(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic command line argument
    s = arger_mips.path_generator.entry_point(args = ['aaa', angr.StringSpec(sym_length=50)], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_mipsel():
    r_addr = 0x400768
    s = arger_mipsel.path_generator.entry_point(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mipsel.path_generator.entry_point(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_mipsel.path_generator.entry_point(args = ['aaa', angr.StringSpec(sym_length=50)], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_i386():
    r_addr = 0x804845B
    s = arger_i386.path_generator.entry_point(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_i386.path_generator.entry_point(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_i386.path_generator.entry_point(args = ['aaa', angr.StringSpec(sym_length=50)], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_amd64():
    r_addr = 0x400571
    s = arger_amd64.path_generator.entry_point(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_amd64.path_generator.entry_point(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_amd64.path_generator.entry_point(args = ['aaa', angr.StringSpec(sym_length=50)], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_arm():
    r_addr = 0x1048c

    s = arger_arm.path_generator.entry_point(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_arm.path_generator.entry_point(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args 
    s = arger_arm.path_generator.entry_point(args = ['aaa', angr.StringSpec(sym_length=50)], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

def test_ppc32():
    r_addr = 0x10000498

    s = arger_ppc32.path_generator.entry_point(args = ['aaa', 'Yan is a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_ppc32.path_generator.entry_point(args = ['aaa', 'Yan is not a noob'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

    # symbolic args
    s = arger_ppc32.path_generator.entry_point(args = ['aaa', angr.StringSpec(sym_length=50)], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    found = xpl.found[0]
    conc = found.state.se.any_str(found.state.mem_expr(found.state.reg_expr('sp'), 400))

    nose.tools.assert_equals("Yan is a noob" in conc, True)

if __name__ == "__main__":
    setup_module()
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    test_ppc32()
