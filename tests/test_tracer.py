import os
import nose
import tracer

import logging
l = logging.getLogger("tracer.tests.test_tracer")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_cgc_0b32aa01_01_raw():
    '''
    Test CGC Scored Event 1's palindrome challenge with raw input
    '''

    # test a valid palindrome
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), "racecar\n")
    result_path, crash_state = t.run()

    # make sure the heap base is correct and hasn't been altered from the default
    nose.tools.assert_equal(result_path.state.cgc.allocation_base, 0xb8000000)

    # make sure there is no crash state
    nose.tools.assert_equal(crash_state, None)

    result_state = result_path.state

    # make sure angr modeled the correct output
    stdout_dump = result_state.posix.dumps(1)
    nose.tools.assert_true(stdout_dump.startswith("\nWelcome to Palindrome Finder\n\n"
                                                  "\tPlease enter a possible palindrome: "
                                                  "\t\tYes, that's a palindrome!\n\n"
                                                  "\tPlease enter a possible palindrome: "))
    # make sure there were no 'Nope's from non-palindromes
    nose.tools.assert_false("Nope" in stdout_dump)

    # now test crashing input
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01"), "A" * 129)
    crash_path, crash_state = t.run()

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)

def test_symbolic_sized_receives():
    '''
    Make sure symbolic sized receives are correctly handled
    '''

    binary_path = os.path.join(bin_location, "tests/cgc/CROMU_00070")
    t = tracer.Tracer(binary_path, "hello")

    # will except if failed
    result_path, crash_state = t.run()

    nose.tools.assert_true(result_path is not None)

    nose.tools.assert_equal(crash_state, None)

    t = tracer.Tracer(binary_path, "\x00" * 20)

    # will except if failed
    result_path, crash_state = t.run()

    nose.tools.assert_true(result_path is not None)

    nose.tools.assert_equal(crash_state, None)

def test_allocation_base_continuity():
    '''
    Make sure the heap base is correct in angr after concrete heap manipulation
    '''

    correct_out = 'prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\nb7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\nb7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\ne: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\na: b7fef000\n'

    t = tracer.Tracer(os.path.join(bin_location, "tests/i386/cgc_allocations"), "")

    path, _ = t.run()

    nose.tools.assert_equal(path.state.posix.dumps(1), correct_out)

def test_crash_detection():
    '''
    Test tracer's ability to detect where (at what address) an input truly caused a crash.
    Caused a bug in unicorn.
    '''

    t = tracer.Tracer(os.path.join(bin_location, "tests/i386/call_symbolic"), "A" * 700)

    _, crash_state = t.run()

    nose.tools.assert_true(crash_state.se.symbolic(crash_state.regs.ip))

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
