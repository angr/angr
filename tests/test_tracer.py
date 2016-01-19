import os
import nose
import tracer

import logging
l = logging.getLogger("tracer.tests.test_tracer")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_cgc_0b32aa01_01_raw():
    '''
    Test CGC Scored Event 1's palindrome challenge with raw input
    '''

    # test a valid palindrome
    t = tracer.Tracer(os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01"), "racecar\n")
    result_path, crash_state = t.run()

    # make sure there is no crash state
    nose.tools.assert_equal(crash_state, None)

    result_state = result_path.state

    # make sure angr modeled the correct output
    stdout_dump = result_state.posix.dumps(1)
    nose.tools.assert_true(stdout_dump.startswith("\t\tYes, that's a palindrome!\n\n"))
    # make sure there were no 'Nope's from non-palindromes
    nose.tools.assert_false("Nope" in stdout_dump)

    # now test crashing input
    t = tracer.Tracer(os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01"), "A" * 129)
    crash_path, crash_state = t.run()

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
