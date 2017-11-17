import os
import gc
import sys
import logging

import nose
import angr
import tracer
import rex.trace_additions
from nose.plugins.attrib import attr


logging.getLogger("angr.simos").setLevel("DEBUG")
logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")


bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))


def test_recursion():
    blob = "00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b1b1adb1b1b1b1b1b1118611981d8611".decode('hex')
    b = os.path.join( os.path.dirname(__file__), "../../binaries/tests/cgc/NRFIN_00075")
    r = tracer.QEMURunner(binary=b, input=blob)
    p = angr.Project(b)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    s = p.factory.tracer_state(input_content=blob)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    crash_path = t.predecessors[-1]
    crash_state = simgr.one_crashed

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)


@attr(speed='slow')
def test_cache_stall():
    # test a valid palindrome
    b = os.path.join(bin_location, "tests/cgc/CROMU_00071")
    blob = "0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c".decode('hex')
    r = tracer.QEMURunner(binary=b, input=blob)
    p = angr.Project(b)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    s = p.factory.tracer_state(input_content=blob, magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    rex.trace_additions.ZenPlugin.prep_tracer(s)
    simgr.run()

    crash_path = t.predecessors[-1]
    crash_state = simgr.crashed[0]

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)

    # load it again
    r = tracer.QEMURunner(binary=b, input=blob)
    s = p.factory.tracer_state(input_content=blob, magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    rex.trace_additions.ZenPlugin.prep_tracer(s)
    simgr.run()

    crash_path = t.predecessors[-1]
    crash_state = simgr.one_crashed

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)


@attr(speed='slow')
def test_manual_recursion():
    b = os.path.join(bin_location, "tests/cgc", "CROMU_00071")

    blob = open(os.path.join(bin_location, 'tests_data/', 'crash2731')).read()
    r = tracer.QEMURunner(binary=b, input=blob)
    p = angr.Project(b)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    s = p.factory.tracer_state(input_content=blob, magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    crash_path = t.predecessors[-1]
    crash_state = simgr.one_crashed

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)


def test_cgc_se1_palindrome_raw():
    b = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")
    # test a valid palindrome
    r = tracer.QEMURunner(binary=b, input="racecar\n")
    p = angr.Project(b)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    s = p.factory.tracer_state(input_content="racecar\n", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    # make sure the heap base is correct and hasn't been altered from the default
    nose.tools.assert_true('traced' in simgr.stashes)
    nose.tools.assert_equal(simgr.traced[0].cgc.allocation_base, 0xb8000000)

    # make sure there is no crash state
    nose.tools.assert_true('crashed' not in simgr.stashes)

    # make sure angr modeled the correct output
    stdout_dump = simgr.traced[0].posix.dumps(1)
    nose.tools.assert_true(stdout_dump.startswith("\nWelcome to Palindrome Finder\n\n"
                                                  "\tPlease enter a possible palindrome: "
                                                  "\t\tYes, that's a palindrome!\n\n"
                                                  "\tPlease enter a possible palindrome: "))
    # make sure there were no 'Nope's from non-palindromes
    nose.tools.assert_false("Nope" in stdout_dump)

    # now test crashing input
    r = tracer.QEMURunner(binary=b, input="A" * 129)
    s = p.factory.tracer_state(input_content="A" * 129, magic_content=r.magic)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    nose.tools.assert_true('crashed' in simgr.stashes)


def test_symbolic_sized_receives():
    b = os.path.join(bin_location, "tests/cgc/CROMU_00070")
    r = tracer.QEMURunner(binary=b, input="hello")
    p = angr.Project(b)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    s = p.factory.tracer_state(input_content="hello", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    # will except if failed
    nose.tools.assert_true('crashed' not in simgr.stashes)
    nose.tools.assert_true('traced' in simgr.stashes)

    r = tracer.QEMURunner(binary=b, input="\x00" * 20)
    s = p.factory.tracer_state(input_content="\x00" * 20)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    # will except if failed
    nose.tools.assert_true('crashed' not in simgr.stashes)
    nose.tools.assert_true('traced' in simgr.stashes)


def test_allocation_base_continuity():
    correct_out = 'prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\nb7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\nb7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\ne: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\na: b7fef000\n'

    b = os.path.join(bin_location, "tests/i386/cgc_allocations")
    r = tracer.QEMURunner(binary=b, input="")
    p = angr.Project(b)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    s = p.factory.tracer_state(input_content="", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    nose.tools.assert_equal(simgr.traced[0].posix.dumps(1), correct_out)


def test_crash_addr_detection():
    b = os.path.join(bin_location, "tests/i386/call_symbolic")
    r = tracer.QEMURunner(binary=b, input="A" * 700)
    p = angr.Project(b)
    p._simos.syscall_library.procedures.update(angr.TRACER_CGC_SYSCALLS)
    s = p.factory.tracer_state(input_content="A" * 700, magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    nose.tools.assert_true('crashed' in simgr.stashes)
    nose.tools.assert_true(simgr.crashed[0].se.symbolic(simgr.crashed[0].regs.ip))


def test_fauxware():
    b = os.path.join(bin_location, "tests/x86_64/fauxware")
    r = tracer.QEMURunner(binary=b, input="A")
    p = angr.Project(b)
    s = p.factory.tracer_state(input_content="A", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace,
                                                 crash_mode=r.crash_mode,
                                                 crash_addr=r.crash_addr)
    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    simgr.run()

    nose.tools.assert_true('traced' in simgr.stashes)


def run_all():
    def print_test_name(name):
        print '#' * (len(name) + 8)
        print '###', name, '###'
        print '#' * (len(name) + 8)
    
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print_test_name(f)
            all_functions[f]()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
