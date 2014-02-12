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
fauxware_amd64 = None
fauxware_ppc32 = None
fauxware_arm = None
fauxware_mipsel = None


def setup_module():
    global fauxware_amd64, fauxware_ppc32, fauxware_arm, fauxware_mipsel
    fauxware_amd64 = angr.Project(
        test_location +
        "/fauxware/fauxware-amd64",
        load_libs=False,
        default_analysis_mode='symbolic',
        use_sim_procedures=True)
    fauxware_ppc32 = angr.Project(
        test_location +
        "/fauxware/fauxware-ppc32",
        load_libs=False,
        default_analysis_mode='symbolic',
        use_sim_procedures=True,
        arch="PPC32")
    fauxware_arm = angr.Project(
        test_location +
        "/fauxware/fauxware-arm",
        load_libs=False,
        default_analysis_mode='symbolic',
        use_sim_procedures=True,
        arch="ARM")
    fauxware_mipsel = angr.Project(
        test_location +
        "/fauxware/fauxware-mipsel",
        load_libs=False,
        default_analysis_mode='symbolic',
        use_sim_procedures=True,
        arch="MIPS32")


def test_amd64():
    results = fauxware_amd64.explore(
        fauxware_amd64.initial_exit(),
        find=(0x4006ed,
              ),
        avoid=(0x4006aa,
               0x4006fd),
        max_repeats=10)
    stdin = results['found'][0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal(
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
        stdin)


def test_ppc32():
    results = fauxware_ppc32.explore(
        fauxware_ppc32.initial_exit(),
        find=(0x1000060C,
              ),
        avoid=(0x10000644,
               0x1000059C),
        max_repeats=10)
    stdin = results['found'][0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal(
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
        stdin)


def test_arm():
    results = fauxware_arm.explore(
        fauxware_arm.initial_exit(),
        find=(0x85F0,
              ),
        avoid=(0x857C,
               0x860C),
        max_repeats=10)
    stdin = results['found'][0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal(
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
        stdin)


def test_mipsel():
    results = fauxware_mipsel.explore(
        fauxware_mipsel.initial_exit(),
        find=(0x004007D4,
              ),
        avoid=(0x00400734,
               0x00400828),
        max_repeats=10)
    stdin = results['found'][0].last_run.initial_state['posix'].dumps(0)
    nose.tools.assert_in("SOSNEAKY", stdin)
    nose.tools.assert_equal(
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
        stdin)

if __name__ == "__main__":
    setup_module()
    test_amd64()
