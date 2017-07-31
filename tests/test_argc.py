import nose
import angr

import logging
l = logging.getLogger("angr_tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_mips():
    arger_mips = angr.Project(test_location + "/mips/argc_decide")
    r_addr = 0x4006f4

    s = arger_mips.factory.entry_state(args = ['aaa'], env = {"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mips.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_mips.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_mipsel():
    arger_mipsel = angr.Project(test_location + "/mipsel/argc_decide")
    r_addr = 0x40070c
    s = arger_mipsel.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_mipsel.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_mipsel.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_i386():
    arger_i386 = angr.Project(test_location + "/i386/argc_decide")
    r_addr = 0x80483d4
    s = arger_i386.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_i386.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_i386.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_amd64():
    arger_amd64 = angr.Project(test_location + "/x86_64/argc_decide")
    r_addr = 0x4004c7
    s = arger_amd64.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_amd64.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_amd64.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_arm():
    arger_arm = angr.Project(test_location + "/armel/argc_decide")
    r_addr = 0x1040c

    s = arger_arm.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_arm.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_arm.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

def test_ppc32():
    arger_ppc32 = angr.Project(test_location + "/ppc/argc_decide")
    r_addr = 0x10000404

    s = arger_ppc32.factory.entry_state(args = ['aaa'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 1)

    s = arger_ppc32.factory.entry_state(args = ['aaa', 'bbb'], env ={"HOME": "/home/angr"})
    xpl = arger_ppc32.surveyors.Explorer(find=[r_addr], start=s)
    xpl.run()

    nose.tools.assert_equals(len(xpl.found), 0)

if __name__ == "__main__":
    test_mips()
    test_mipsel()
    test_arm()
    test_i386()
    test_amd64()
    test_ppc32()
