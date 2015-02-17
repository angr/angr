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
    arger_ppc32 = angr.Project(test_location + "/blob/ppc/argc_decide")

def setup_mips():
    global arger_mips
    arger_mips = angr.Project(test_location + "/blob/mips/argc_decide")

def setup_mipsel():
    global arger_mipsel
    arger_mipsel = angr.Project(test_location + "/blob/mipsel/argc_decide")

def setup_amd64():
    global arger_amd64
    arger_amd64 = angr.Project(test_location + "/blob/x86_64/argc_decide")

def setup_i386():
    global arger_i386
    arger_i386 = angr.Project(test_location + "/blob/i386/argc_decide")

def setup_arm():
    global arger_arm
    arger_arm = angr.Project(test_location + "/blob/armel/argc_decide")

def setup_module():
    setup_i386()
    setup_amd64()
    setup_mipsel()
    setup_mips()
    setup_arm()
    setup_ppc32()

def test_mips():
    r_addr = 0x4006f4

    s = arger_mips.path_generator.entry_point(args = ['aaa'], env = {"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mips.path_generator.entry_point(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_mipsel():
    r_addr = 0x40070c
    s = arger_mipsel.path_generator.entry_point(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mipsel.path_generator.entry_point(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_i386():
    r_addr = 0x80483d4
    s = arger_i386.path_generator.entry_point(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_i386.path_generator.entry_point(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_amd64():
    r_addr = 0x4004c7
    s = arger_amd64.path_generator.entry_point(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_amd64.path_generator.entry_point(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_arm():
    r_addr = 0x1040c

    s = arger_arm.path_generator.entry_point(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_arm.path_generator.entry_point(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_ppc32():
    r_addr = 0x10000404

    s = arger_ppc32.path_generator.entry_point(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_ppc32.path_generator.entry_point(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

if __name__ == "__main__":
    setup_module()
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    # ppc32 doesn't work for now
    #test_ppc32()
