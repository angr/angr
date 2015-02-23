#!/usr/bin/env python

import os
import logging
import time
import pickle
import sys

l = logging.getLogger("angr.tests.test_simcc")

import nose
import pprint
import networkx

try:
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr
from simuvex.s_cc import SimCCSystemVAMD64

# Load the tests
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def _test_simcc_x86_64():
    binary_path = test_location + "/blob/x86_64/simcc"

    p = angr.Project(binary_path)
    cfg = p.analyses.CFG()

    fm = cfg.function_manager

    f_arg1 = fm.function(name='arg1')
    nose.tools.assert_not_equal(f_arg1, None)
    nose.tools.assert_equal(type(f_arg1.cc), SimCCSystemVAMD64)
    nose.tools.assert_equal(len(f_arg1.arguments), 1)
    nose.tools.assert_equal(f_arg1.arguments[0].name, 'rdi')

    f_arg7 = fm.function(name='arg7')
    nose.tools.assert_not_equal(f_arg7, None)
    nose.tools.assert_equal(type(f_arg7.cc), SimCCSystemVAMD64)
    nose.tools.assert_equal(len(f_arg7.arguments), 7)
    nose.tools.assert_equal(f_arg7.arguments[1].name, 'rsi')

    f_arg9 = fm.function(name='arg9')
    nose.tools.assert_not_equal(f_arg9, None)
    nose.tools.assert_equal(type(f_arg9.cc), SimCCSystemVAMD64)
    nose.tools.assert_equal(len(f_arg9.arguments), 9)
    nose.tools.assert_equal(f_arg9.arguments[8].offset, 0x10 + 0x8 * 2)

def test_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('_test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['_test_' + sys.argv[1]]()
    else:
        test_all()
