import nose
import angr

import os
import logging

l = logging.getLogger('angr.tests.test_file_struct_funcs')

test_location = os.path.dirname(os.path.realpath(__file__))


def check_state_1(state):
    # Need to dump file.txt by path because program closes it
    return state.posix.dump_file_by_path('file.txt') == b"testing abcdef" and \
           state.posix.dumps(0)[:4] == b"xyz\n" and \
           state.posix.dumps(1) == b"good1\n" and \
           state.posix.dumps(2) == b""


def check_state_2(state):
    return state.posix.dump_file_by_path('file.txt') == b"testing abcdef" and \
           state.posix.dumps(0)[:4] == b"wxyz" and \
           state.posix.dumps(1) == b"" and \
           state.posix.dumps(2) == b"good2\n"


def check_state_3(state):
    return state.posix.dump_file_by_path('file.txt') == b"testing abcdef" and \
           state.posix.dumps(1) == b"" and \
           state.posix.dumps(2) == b""


def test_file_struct_funcs():
    test_bin = os.path.join(test_location, '..', '..', 'binaries', 'tests', 'x86_64', 'file_func_test')
    b = angr.Project(test_bin)

    pg = b.factory.simulation_manager()
    pg.active[0].options.discard("LAZY_SOLVES")
    pg.explore()

    nose.tools.assert_equal(len(pg.deadended), 3)

    for p in pg.deadended:
        nose.tools.assert_true(check_state_1(p) or check_state_2(p) or check_state_3(p))


if __name__ == "__main__":
    test_file_struct_funcs()
