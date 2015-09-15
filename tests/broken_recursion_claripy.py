#!/usr/bin/env python

import logging
l = logging.getLogger("angr_tests")

import nose
import angr

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
recursion_nolibs = None

def setup_module():
    global recursion_nolibs
    recursion_nolibs = angr.Project(test_location + "/temp", load_options={'auto_load_libs': False})

def test_claripy_recursion_depth():
    cfg = recursion_nolibs.analyses.CFG()
    try:
        vfg = recursion_nolibs.analyses.VFG(cfg, interfunction_level=3)
    except:
        nose.tools.assert_true(False)
    
    nose.tools.assert_true(True) 

if __name__ == '__main__':
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass
    setup_module()
    test_claripy_recursion_depth()
