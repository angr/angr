import nose
import angr

import logging
l = logging.getLogger('angr.tests.test_signed_div')

import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def check_state_1(state):
    return state.posix.dumps(3) == "testing abcdef" and \
           state.posix.dumps(0)[:4] == "xyz\n" and \
           state.posix.dumps(1) == "good1\n" and \
           state.posix.dumps(2) == ""

def check_state_2(state):
    return state.posix.dumps(3) == "testing abcdef" and \
           state.posix.dumps(0)[:4] == "wxyz" and \
           state.posix.dumps(1) == "" and \
           state.posix.dumps(2) == "good2\n"

def check_state_3(state):
    return state.posix.dumps(3) == "testing abcdef" and \
           state.posix.dumps(1) == "" and \
           state.posix.dumps(2) == ""

def run_test_file_struct_funcs():
    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/file_func_test")
    b = angr.Project(test_bin)

    pg = b.factory.path_group()
    pg.active[0].state.options.discard("LAZY_SOLVES")
    pg.explore()

    nose.tools.assert_equal(len(pg.deadended), 3)

    for p in pg.deadended:
        nose.tools.assert_true(check_state_1(p.state) or check_state_2(p.state) or check_state_3(p.state))

def test_file_struct_funcs():
    yield run_test_file_struct_funcs

if __name__ == "__main__":
    run_test_file_struct_funcs()
