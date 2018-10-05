from __future__ import print_function
import os
import sys
import logging

import nose
import angr

from common import bin_location, do_trace, slow_test

def tracer_cgc(filename, test_name, stdin):
    p = angr.Project(filename)
    p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

    trace, magic, crash_mode, crash_addr = do_trace(p, test_name, stdin)
    s = p.factory.entry_state(mode='tracing', stdin=angr.SimFileStream, flag_page=magic)
    s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

    simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=crash_mode)
    t = angr.exploration_techniques.Tracer(trace, crash_addr=crash_addr)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    return simgr, t

def tracer_linux(filename, test_name, stdin):
    p = angr.Project(filename)

    trace, _, crash_mode, crash_addr = do_trace(p, test_name, stdin, ld_linux=p.loader.linux_loader_object.binary, library_path=set(os.path.dirname(obj.binary) for obj in p.loader.all_elf_objects), record_stdout=True)
    s = p.factory.entry_state(mode='tracing', stdin=angr.SimFileStream)
    s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

    simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=crash_mode)
    t = angr.exploration_techniques.Tracer(trace, crash_addr=crash_addr)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    return simgr, t

def test_recursion():
    blob = bytes.fromhex("00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b1b1adb1b1b1b1b1b1118611981d8611")
    fname = os.path.join(os.path.dirname(__file__), "../../binaries/tests/cgc/NRFIN_00075")

    simgr, _ = tracer_cgc(fname, 'tracer_recursion', blob)
    simgr.run()

    nose.tools.assert_true(simgr.crashed)
    nose.tools.assert_true(simgr.crashed[0].solver.symbolic(simgr.crashed[0].regs.ip))


@slow_test
def broken_cache_stall():
    # test a valid palindrome
    b = os.path.join(bin_location, "tests/cgc/CROMU_00071")
    blob = bytes.fromhex("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c")

    simgr, tracer = tracer_cgc(b, 'tracer_cache_stall', blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.crashed[0]

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)

    # load it again
    simgr, tracer = tracer_cgc(b, 'tracer_cache_stall', blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.one_crashed

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)


def test_manual_recursion():

    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    b = os.path.join(bin_location, "tests/cgc", "CROMU_00071")
    blob = open(os.path.join(bin_location, 'tests_data/', 'crash2731'), 'rb').read()

    simgr, tracer = tracer_cgc(b, 'tracer_manual_recursion', blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.one_crashed

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)


def test_cgc_se1_palindrome_raw():
    b = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")
    # test a valid palindrome

    simgr, _ = tracer_cgc(b, 'tracer_cgc_se1_palindrome_raw_nocrash', b'racecar\n')
    simgr.run()

    # make sure the heap base is correct and hasn't been altered from the default
    nose.tools.assert_true('traced' in simgr.stashes)
    nose.tools.assert_equal(simgr.traced[0].cgc.allocation_base, 0xb8000000)

    # make sure there is no crash state
    nose.tools.assert_false(simgr.crashed)

    # make sure angr modeled the correct output
    stdout_dump = simgr.traced[0].posix.dumps(1)
    nose.tools.assert_true(stdout_dump.startswith(b"\nWelcome to Palindrome Finder\n\n"
                                                  b"\tPlease enter a possible palindrome: "
                                                  b"\t\tYes, that's a palindrome!\n\n"
                                                  b"\tPlease enter a possible palindrome: "))
    # make sure there were no 'Nope's from non-palindromes
    nose.tools.assert_false(b"Nope" in stdout_dump)

    # now test crashing input
    simgr, _ = tracer_cgc(b, 'tracer_cgc_se1_palindrome_raw_yescrash', b'A'*129)
    simgr.run()

    nose.tools.assert_true(simgr.crashed)


def test_symbolic_sized_receives():
    b = os.path.join(bin_location, "tests/cgc/CROMU_00070")

    simgr, _ = tracer_cgc(b, 'tracer_symbolic_sized_receives', b'hello')
    simgr.run()

    nose.tools.assert_false(simgr.crashed)
    nose.tools.assert_true('traced' in simgr.stashes)

    simgr, _ = tracer_cgc(b, 'tracer_symbolic_sized_receives_nulls', b'\0'*20)
    simgr.run()

    nose.tools.assert_false(simgr.crashed)
    nose.tools.assert_true('traced' in simgr.stashes)


def test_allocation_base_continuity():
    correct_out = b'prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\nb7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\nb7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\ne: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\na: b7fef000\n'

    b = os.path.join(bin_location, "tests/i386/cgc_allocations")

    simgr, _ = tracer_cgc(b, 'tracer_allocation_base_continuity', b'')
    simgr.run()

    nose.tools.assert_equal(simgr.traced[0].posix.dumps(1), correct_out)


def test_crash_addr_detection():
    b = os.path.join(bin_location, "tests/i386/call_symbolic")

    simgr, _ = tracer_cgc(b, 'tracer_crash_addr_detection', b'A'*700)
    simgr.run()

    nose.tools.assert_true(simgr.crashed)
    nose.tools.assert_true(simgr.crashed[0].solver.symbolic(simgr.crashed[0].regs.ip))


def test_fauxware():

    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    b = os.path.join(bin_location, "tests/x86_64/fauxware")
    simgr, _ = tracer_linux(b, 'tracer_fauxware', b'A')
    simgr.run()

    nose.tools.assert_true('traced' in simgr.stashes)


def run_all():
    def print_test_name(name):
        print('#' * (len(name) + 8))
        print('###', name, '###')
        print('#' * (len(name) + 8))

    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print_test_name(f)
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
