import nose
import os

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_iat():
    p = angr.Project(os.path.join(test_location, 'i386', 'simple_windows.exe'), auto_load_libs=False)
    cfg = p.analyses.CFGFast()

    strcmp_caller_bb = cfg.get_any_node(0x401010)
    nose.tools.assert_equal(len(strcmp_caller_bb.successors), 1)

    strcmp = strcmp_caller_bb.successors[0]
    nose.tools.assert_true(strcmp.is_simprocedure)
    nose.tools.assert_equal(strcmp.simprocedure_name, 'strcmp')

    strcmp_successors = strcmp.successors
    nose.tools.assert_equal(len(strcmp_successors), 1)

    strcmp_ret_to = strcmp_successors[0]
    nose.tools.assert_equal(strcmp_ret_to.addr, 0x40102a)

if __name__ == '__main__':
    test_iat()
