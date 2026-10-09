import logging

l = logging.getLogger("angr_tests")

import nose
import angr

# load the tests
import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
vfg_1_nolibs = None

def setup_module():
    global vfg_1_nolibs
    vfg_1_nolibs = angr.Project(test_location + "/x86_64/vfg_1", load_options={'auto_load_libs': False})

def test_simuvex_strided_interval_noitem():
    cfg = vfg_1_nolibs.analyses.CFG()
    cfg.normalize()
    try:
    	vfg = vfg_1_nolibs.analyses.VFG(cfg, context_sensitivity_level=3, interfunction_level=4, record_function_final_states=True)
    except:
        # AttributeError: 'StridedInterval' object has no attribute 'items'
        nose.tools.assert_true(False)

if __name__ == '__main__':
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass
    setup_module()
    test_simuvex_strided_interval_noitem()
