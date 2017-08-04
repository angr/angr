import os
import nose
import angr
import rex.trace_additions

import logging
logging.getLogger("angr.analyses.tracer.tracer").setLevel('DEBUG')

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_cgc_se1_palindrome_raw():
    # Test CGC Scored Event 1's palindrome challenge with raw input
    #import ipdb; ipdb.set_trace()

    # test a valid palindrome
    p = angr.Project(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"))
    t = p.analyses.Tracer("racecar\n")
    result_state, crash_state = t.run()

    # make sure the heap base is correct and hasn't been altered from the default
    nose.tools.assert_equal(result_state.cgc.allocation_base, 0xb8000000)

    # make sure there is no crash state
    nose.tools.assert_equal(crash_state, None)

    # make sure angr modeled the correct output
    stdout_dump = result_state.posix.dumps(1)
    nose.tools.assert_true(stdout_dump.startswith("\nWelcome to Palindrome Finder\n\n"
                                                  "\tPlease enter a possible palindrome: "
                                                  "\t\tYes, that's a palindrome!\n\n"
                                                  "\tPlease enter a possible palindrome: "))
    # make sure there were no 'Nope's from non-palindromes
    nose.tools.assert_false("Nope" in stdout_dump)

    # now test crashing input
    p = angr.Project(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"))
    t = p.analyses.Tracer("A" * 129)
    result_state, crash_state = t.run()

    nose.tools.assert_not_equal(result_state, None)
    nose.tools.assert_not_equal(crash_state, None)

def test_symbolic_sized_receives():
    binary_path = os.path.join(bin_location, "tests/cgc/CROMU_00070")
    p = angr.Project(binary_path)
    t = p.analyses.Tracer("hello")

    # will except if failed
    result_state, crash_state = t.run()

    nose.tools.assert_true(result_state is not None)
    nose.tools.assert_equal(crash_state, None)

    t = p.analyses.Tracer("\x00" * 20)

    # will except if failed
    result_state, crash_state = t.run()

    nose.tools.assert_true(result_state is not None)
    nose.tools.assert_equal(crash_state, None)

def test_allocation_base_continuity():
    correct_out = 'prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\nb7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\nb7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\ne: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\na: b7fef000\n'

    p = angr.Project(os.path.join(bin_location, "tests/i386/cgc_allocations"))
    t = p.analyses.Tracer("")
    state, _ = t.run()

    nose.tools.assert_equal(state.posix.dumps(1), correct_out)

def test_crash_addr_detection():
    p = angr.Project(os.path.join(bin_location, "tests/i386/call_symbolic"))
    t = p.analyses.Tracer("A" * 700)
    _, crash_state = t.run()

    nose.tools.assert_true(crash_state.se.symbolic(crash_state.regs.ip))

def test_recursion():
    blob = "00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b1b1adb1b1b1b1b1b1118611981d8611".decode('hex')

    p = angr.Project(os.path.join(bin_location, "tests/cgc/NRFIN_00075"))
    t = p.analyses.Tracer(blob)
    t.run()

def test_cache_stall():
    # test a valid palindrome
    p = angr.Project(os.path.join(bin_location, "tests/cgc/CROMU_00071"))
    t = p.analyses.Tracer("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c".decode('hex'))
    rex.trace_additions.ZenPlugin.prep_tracer(t)
    crash_path, crash_state = t.run()

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)

    # load it again
#   t = p.analyses.Tracer("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c".decode('hex'))
#   rex.trace_additions.ZenPlugin.prep_tracer(t)
#   crash_path, crash_state = t.run()

#   nose.tools.assert_not_equal(crash_path, None)
#   nose.tools.assert_not_equal(crash_state, None)

def test_manual_recursion():
    p = angr.Project(os.path.join(bin_location, "tests/cgc/CROMU_00071"))
    t = p.analyses.Tracer(open('crash2731').read())

    t.run()

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
