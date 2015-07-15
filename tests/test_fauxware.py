import nose
import angr

import logging
l = logging.getLogger("angr.tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_x86():
    fauxware_x86 = angr.Project(test_location + "/i386/fauxware", default_analysis_mode='symbolic')
    results = angr.surveyors.Explorer(fauxware_x86, find=(0x080485C9,), avoid=(0x080485DD,0x08048564), max_repeats=10).run()
    stdin = results.found[0].state.posix.dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_amd64():
    fauxware_amd64 = angr.Project(test_location + "/x86_64/fauxware", default_analysis_mode='symbolic', use_sim_procedures=True)
    results = angr.surveyors.Explorer(fauxware_amd64, find=(0x4006ed,), avoid=(0x4006aa,0x4006fd), max_repeats=10).run()
    stdin = results.found[0].state.posix.dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_ppc32():
    fauxware_ppc32 = angr.Project(test_location + "/ppc/fauxware", default_analysis_mode='symbolic')
    results = angr.surveyors.Explorer(fauxware_ppc32, find=(0x1000060C,), avoid=(0x10000644,0x1000059C), max_repeats=10).run()
    stdin = results.found[0].state.posix.dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_arm():
    fauxware_arm = angr.Project(test_location + "/armel/fauxware", default_analysis_mode='symbolic')
    results = angr.surveyors.Explorer(fauxware_arm, find=(0x85F0,), avoid=(0x86F8,0x857C), max_repeats=10).run()
    stdin = results.found[0].state.posix.dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def test_mips():
    fauxware_mips = angr.Project(test_location + "/mips/fauxware", default_analysis_mode='symbolic')
    results = angr.surveyors.Explorer(fauxware_mips, find=(0x4009FC,), avoid=(0x400A10,0x400774), max_repeats=10).run()
    stdin = results.found[0].state.posix.dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

if __name__ == "__main__":
    test_amd64()
    test_x86()
    test_arm()
    test_ppc32()
    test_mips()
