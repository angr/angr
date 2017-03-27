import nose
import angr
import os

import logging
l = logging.getLogger("angr_tests")

test_location = str(os.path.dirname(os.path.realpath(__file__)))

def run_test_file_struct_funcs():
    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/test_multi_open_file")
    b = angr.Project(test_bin)

    pg = b.factory.path_group()
    pg.active[0].state.options.discard("LAZY_SOLVES")
    pg.explore()

    nose.tools.assert_equal(len(pg.deadended), 1)

    for p in pg.deadended:
        nose.tools.assert_true(p.state.posix.dumps(2) == "")


def test_file_struct_funcs():
    yield run_test_file_struct_funcs

if __name__ == "__main__":
    run_test_file_struct_funcs()
