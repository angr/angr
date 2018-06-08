import nose
import angr

import os
import logging

l = logging.getLogger('angr.tests.test_file_struct_funcs')

test_location = str(os.path.dirname(os.path.realpath(__file__)))


def check_state_1(state):
    # Need to dump file.txt by path because program closes it
    return state.posix.dump_file_by_path('file.txt') == "testing abcdef" and \
           state.posix.dumps(0)[:4] == "xyz\n" and \
           state.posix.dumps(1) == "good1\n" and \
           state.posix.dumps(2) == ""


def check_state_2(state):
    return state.posix.dump_file_by_path('file.txt') == "testing abcdef" and \
           state.posix.dumps(0)[:4] == "wxyz" and \
           state.posix.dumps(1) == "" and \
           state.posix.dumps(2) == "good2\n"


def check_state_3(state):
    return state.posix.dump_file_by_path('file.txt') == "testing abcdef" and \
           state.posix.dumps(1) == "" and \
           state.posix.dumps(2) == ""


def test_file_struct_funcs():
    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/file_func_test")
    b = angr.Project(test_bin)

    pg = b.factory.simgr()
    pg.active[0].options.discard("LAZY_SOLVES")
    pg.explore()

    nose.tools.assert_equal(len(pg.deadended), 3)

    for p in pg.deadended:
        nose.tools.assert_true(check_state_1(p) or check_state_2(p) or check_state_3(p))


if __name__ == "__main__":
    test_file_struct_funcs()
