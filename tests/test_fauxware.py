#!/usr/bin/env python

import nose
import logging
l = logging.getLogger("angr.tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr, simuvex

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
fauxware_x86 = None
fauxware_amd64 = None
fauxware_ppc32 = None
fauxware_arm = None
fauxware_mips = None

def setup_x86():
    global fauxware_x86
    fauxware_x86 = angr.Project(test_location + "/build/i386/fauxware", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch="X86")
def setup_amd64():
    global fauxware_amd64
    fauxware_amd64 = angr.Project(test_location + "/build/x86_64/fauxware", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True)
def setup_ppc32():
    global fauxware_ppc32
    fauxware_ppc32 = angr.Project(test_location + "/build/ppc/fauxware", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch="PPC32")
def setup_mips():
    global fauxware_mips
    fauxware_mips = angr.Project(test_location + "/build/mips/fauxware", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch=simuvex.SimMIPS32(endness="Iend_BE"))
def setup_arm():
    global fauxware_arm
    fauxware_arm = angr.Project(test_location + "/build/armel/fauxware", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True, arch=simuvex.SimARM(endness="Iend_LE"))

def setup_module():
    setup_x86()
    setup_amd64()
    setup_arm()
    setup_ppc32()
    setup_mips()

def test_x86():
    results = angr.surveyors.Explorer(fauxware_x86, find=(0x080485C9,), avoid=(0x080485DD,0x08048564), max_repeats=10).run()
    stdin = results.found[0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_amd64():
    results = angr.surveyors.Explorer(fauxware_amd64, find=(0x4006ed,), avoid=(0x4006aa,0x4006fd), max_repeats=10).run()
    stdin = results.found[0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_ppc32():
    results = angr.surveyors.Explorer(fauxware_ppc32, find=(0x1000060C,), avoid=(0x10000644,0x1000059C), max_repeats=10).run()
    stdin = results.found[0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_arm():
    results = angr.surveyors.Explorer(fauxware_arm, find=(0x85F0,), avoid=(0x86F8,0x857C), max_repeats=10).run()
    stdin = results.found[0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_mips():
    results = angr.surveyors.Explorer(fauxware_mips, find=(0x4009FC,), avoid=(0x400A10,0x400774), max_repeats=10).run()
    stdin = results.found[0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

if __name__ == "__main__":
    import sys
    arch = sys.argv[1] if len(sys.argv) > 1 else "amd64"

    globals()['setup_'+arch]()
    l.info("LOADED")
    globals()['test_'+arch]()
    l.info("DONE")
