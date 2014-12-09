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

    s = arger_mips.initial_state(argv = ['aaa'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_mips, find=[r_addr], start=arger_mips.exit_to(arger_mips.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mips.initial_state(argv = ['aaa', 'bbb'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_mips, find=[r_addr], start=arger_mips.exit_to(arger_mips.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_mipsel():
    r_addr = 0x40070c
    s = arger_mipsel.initial_state(argv = ['aaa', 'bbb'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_mipsel, find=[r_addr], start=arger_mipsel.exit_to(arger_mipsel.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mipsel.initial_state(argv = ['aaa'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_mipsel, find=[r_addr], start=arger_mipsel.exit_to(arger_mipsel.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_i386():
    r_addr = 0x80483d4
    s = arger_i386.initial_state(argv = ['aaa'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_i386, find=[r_addr], start=arger_i386.exit_to(arger_i386.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_i386.initial_state(argv = ['aaa', 'bbb'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_i386, find=[r_addr], start=arger_i386.exit_to(arger_i386.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_amd64():
    r_addr = 0x4004c7
    s = arger_amd64.initial_state(argv = ['aaa'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_amd64, find=[r_addr], start=arger_amd64.exit_to(arger_amd64.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_amd64.initial_state(argv = ['aaa', 'bbb'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_amd64, find=[r_addr], start=arger_amd64.exit_to(arger_amd64.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_arm():
    r_addr = 0x1040c

    s = arger_arm.initial_state(argv = ['aaa'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_arm, find=[r_addr], start=arger_arm.exit_to(arger_arm.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_arm.initial_state(argv = ['aaa', 'bbb'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_arm, find=[r_addr], start=arger_arm.exit_to(arger_arm.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_ppc32():
    r_addr = 0x10000404

    s = arger_ppc32.initial_state(argv = ['aaa'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_ppc32, find=[r_addr], start=arger_ppc32.exit_to(arger_ppc32.entry, state=s))
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_ppc32.initial_state(argv = ['aaa', 'bbb'], envp ={"HOME": "/home/angr"})
    xpl = angr.surveyors.Explorer(arger_ppc32, find=[r_addr], start=arger_ppc32.exit_to(arger_ppc32.entry, state=s))
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
