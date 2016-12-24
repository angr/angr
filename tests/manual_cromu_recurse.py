import os
import nose
import tracer

import logging
l = logging.getLogger("tracer.tests.test_tracer")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
pov_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "povs"))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))

logging.getLogger("tracer").setLevel("DEBUG")

def test_recursion():
    t = tracer.Tracer(os.path.join(bin_location, "cgc", "CROMU_00071"), open('crash2731').read())

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
