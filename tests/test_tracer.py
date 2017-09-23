import os
import nose
import angr
import rex.trace_additions
import gc

import logging
logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
logging.getLogger("angr.simos").setLevel("DEBUG")
logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_recursion():
    blob = "00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b1b1adb1b1b1b1b1b1118611981d8611".decode('hex')
    b = os.path.join( os.path.dirname(__file__), "../../binaries/tests/cgc/NRFIN_00075")
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input=blob)
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content=blob)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()

   #print t.results
    print simgr.stashes

def test_cache_stall():
    # test a valid palindrome
    b = os.path.join(bin_location, "tests/cgc/CROMU_00071")
    blob = "0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c".decode('hex')
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input=blob)
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content=blob)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    rex.trace_additions.ZenPlugin.prep_tracer(t)
    simgr.run()

    print simgr.stashes
   #crash_path, crash_state = t.results

   #nose.tools.assert_not_equal(crash_path, None)
   #nose.tools.assert_not_equal(crash_state, None)

    # load it again
   #r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input=blob)
   #s = p.factory.tracer_state(input_content=blob)
   #simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
   #simgr.use_technique(t)

   #rex.trace_additions.ZenPlugin.prep_tracer(t)
   #simgr.run()

   #crash_path, crash_state = t.results

   #nose.tools.assert_not_equal(crash_path, None)
   #nose.tools.assert_not_equal(crash_state, None)

def test_manual_recursion():
    b = os.path.join(bin_location, "tests/cgc", "CROMU_00071")
    blob = open('crash2731').read()
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input=blob)
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content=blob, magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()
    print simgr.stashes


def test_cgc_se1_palindrome_raw():
    b = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")
    # test a valid palindrome
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input="racecar\n")
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content="racecar\n", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()
    print simgr.stashes

   #result_state, crash_state = t.results

   ## make sure the heap base is correct and hasn't been altered from the default
   #nose.tools.assert_equal(result_state.cgc.allocation_base, 0xb8000000)

   ## make sure there is no crash state
   #nose.tools.assert_equal(crash_state, None)

   ## make sure angr modeled the correct output
   #stdout_dump = result_state.posix.dumps(1)
   #nose.tools.assert_true(stdout_dump.startswith("\nWelcome to Palindrome Finder\n\n"
   #                                              "\tPlease enter a possible palindrome: "
   #                                              "\t\tYes, that's a palindrome!\n\n"
   #                                              "\tPlease enter a possible palindrome: "))
   ## make sure there were no 'Nope's from non-palindromes
   #nose.tools.assert_false("Nope" in stdout_dump)

    # now test crashing input
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input="A" * 129)
    s = p.factory.tracer_state(input_content="A" * 129, magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()
    print simgr.stashes

   #result_state, crash_state = t.results

   #nose.tools.assert_not_equal(result_state, None)
   #nose.tools.assert_not_equal(crash_state, None)

def test_symbolic_sized_receives():
    b = os.path.join(bin_location, "tests/cgc/CROMU_00070")
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input="hello")
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content="hello", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()
    print simgr.stashes

    # will except if failed
   #result_state, crash_state = t.results

   #nose.tools.assert_true(result_state is not None)
   #nose.tools.assert_equal(crash_state, None)

    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input="\x00" * 20)
    s = p.factory.tracer_state(input_content="\x00" * 20)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()
    print simgr.stashes

    # will except if failed
   #result_state, crash_state = t.results

   #nose.tools.assert_true(result_state is not None)
   #nose.tools.assert_equal(crash_state, None)

def test_allocation_base_continuity():
    correct_out = 'prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\nb7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\nb7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\ne: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\na: b7fef000\n'

    b = os.path.join(bin_location, "tests/i386/cgc_allocations")
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input="")
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content="", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()
    print simgr.stashes

   #state, _ = t.results

   #nose.tools.assert_equal(state.posix.dumps(1), correct_out)

def test_crash_addr_detection():
    b = os.path.join(bin_location, "tests/i386/call_symbolic")
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input="A" * 700)
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content="A" * 700, magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_mode=r.crash_mode)
    simgr.use_technique(c)
    simgr.use_technique(t)

    simgr.run()

   #_, crash_state = t.results

   #nose.tools.assert_true(crash_state.se.symbolic(crash_state.regs.ip))

def test_fauxware():
    b = os.path.join(bin_location, "tests/x86_64/fauxware")
    r = angr.misc.tracer.qemu_runner.QEMURunner(binary=b, input="A")
    p = angr.misc.tracer.make_tracer_project(binary=b)
    s = p.factory.tracer_state(input_content="A", magic_content=r.magic)
    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
   #t = angr.exploration_techniques.Tracer(trace=r.trace, crash_mode=r.crash_mode)
    t = angr.exploration_techniques.Tracer(trace=r.trace)
    simgr.use_technique(t)

    simgr.run()

   #state, _ = t.results
   #print state, state.se.constraints
    print simgr.stashes

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print f
            if f == 'test_cache_stall':
                continue
            all_functions[f]()


if __name__ == "__main__":

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
