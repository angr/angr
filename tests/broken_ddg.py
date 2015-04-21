#!/usr/bin/env python

import os
import logging
import time
import sys

l = logging.getLogger("angr.tests.test_ddg")

import nose
import angr

# Load the tests
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def perform_one(binary_path):
    proj = angr.Project(binary_path,
                        use_sim_procedures=True,
                        default_analysis_mode='symbolic')
    start = time.time()
    cfg = proj.analyses.CFG(context_sensitivity_level=2, keep_input_state=True)
    end = time.time()
    duration = end - start
    l.info("CFG generated in %f seconds.", duration)

    # TODO: This is a very bogus test case. Improve it later.
    ddg = proj.analyses.DDG(cfg)
    nose.tools.assert_true(len(ddg.graph) > 10)


def test_ddg_0():
    binary_path = test_location + "/blob/x86_64/datadep_test"
    perform_one(binary_path)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        all_functions[f]()

if __name__ == "__main__":
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass

    logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.surveyors.Explorer").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.ddg").setLevel(logging.DEBUG)
    # logging.getLogger("s_irsb").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    #logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    #logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()

