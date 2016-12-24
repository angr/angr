import os
import rex.trace_additions
import nose
import tracer

import logging
l = logging.getLogger("tracer.tests.test_cache_stall")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

logging.getLogger("tracer").setLevel("DEBUG")

def test_cache_stall():
    '''
    Test cache restoration stall
    '''

    # test a valid palindrome
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/CROMU_00071"), "0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c".decode('hex'))
    rex.trace_additions.ZenPlugin.prep_tracer(t)
    crash_path, crash_state = t.run()

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)

    # load it again
    t = tracer.Tracer(os.path.join(bin_location, "tests/cgc/CROMU_00071"), "0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c".decode('hex'))
    rex.trace_additions.ZenPlugin.prep_tracer(t)
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

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
