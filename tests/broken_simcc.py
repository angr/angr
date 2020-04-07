import nose
import angr
from angr.calling_conventions import SimCCSystemVAMD64

import logging
l = logging.getLogger("angr.tests.test_simcc")

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_simcc_x86_64():
    binary_path = os.path.join(test_location, 'x86_64', 'simcc')

    p = angr.Project(binary_path)
    p.analyses.CFGEmulated()

    f_arg1 = p.kb.functions['arg1']
    nose.tools.assert_not_equal(f_arg1, None)
    nose.tools.assert_equal(type(f_arg1.calling_convention), SimCCSystemVAMD64)
    nose.tools.assert_equal(len(f_arg1.arguments), 1)
    nose.tools.assert_equal(f_arg1.arguments[0].reg_name, 'rdi')

    f_arg7 = p.kb.functions['arg7']
    nose.tools.assert_not_equal(f_arg7, None)
    nose.tools.assert_equal(type(f_arg7.calling_convention), SimCCSystemVAMD64)
    nose.tools.assert_equal(len(f_arg7.arguments), 7)
    nose.tools.assert_equal(f_arg7.arguments[1].reg_name, 'rsi')

    f_arg9 = p.kb.functions.function(name='arg9')
    nose.tools.assert_not_equal(f_arg9, None)
    nose.tools.assert_equal(type(f_arg9.calling_convention), SimCCSystemVAMD64)
    nose.tools.assert_equal(len(f_arg9.arguments), 9)
    nose.tools.assert_equal(f_arg9.arguments[8].stack_offset, 0x8 + 0x8 * 2)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_') and hasattr(kv[0], '__call__')), functions.items()))
    for f in sorted(all_functions.keys()):
        all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    run_all()
