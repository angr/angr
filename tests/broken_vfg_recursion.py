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

def test_claripy_recursion_depth():
    cfg = vfg_1_nolibs.analyses.CFG()
    cfg.normalize()
    vfg = vfg_1_nolibs.analyses.VFG(cfg, start=0x40059d, function_start=0x40059d, context_sensitivity_level=3, interfunction_level=0, record_function_final_states=True)
    nose.tools.assert_equal({n.addr for n in vfg.graph.nodes()}, {0x4005b0, 0x40059d, 0x4005aa, 0x4005c4, 0x4005c9})
    final_state = vfg.function_final_states[0x40059d].values()[0]
    try:
        final_state.se.any_n_int(final_state.regs.rax, 3)
    except:
        # ClaripyRecursionError: ('Recursion limit reached. I sorry.', <type 'exceptions.RuntimeError'>, RuntimeError('maximum recursion depth exceeded while calling a Python object',))
        nose.tools.assert_true(False)

if __name__ == '__main__':
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass
    setup_module()
    test_claripy_recursion_depth()
