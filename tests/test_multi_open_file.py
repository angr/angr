import nose
import angr
import os

import logging
l = logging.getLogger('angr.tests.test_multi_open_file')

test_location = str(os.path.dirname(os.path.realpath(__file__)))

def run_test_multi_open_file():
    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/test_multi_open_file")
    b = angr.Project(test_bin)

    pg = b.factory.simgr()
    pg.active[0].options.discard("LAZY_SOLVES")
    pg.explore()

    nose.tools.assert_equal(len(pg.deadended), 1)

    # See the source file in binaries/tests_src/test_multi_open_file.c
    # for the tests run
    for p in pg.deadended:
        nose.tools.assert_true(p.posix.dumps(2) == "")

        # Check that the temp file has what should be written to it
        for path, f in p.posix.fs.iteritems():
            if 'tmp' in path:
                nose.tools.assert_true(p.posix.dump_file_by_path(path) == "foobar and baz")


def test_multi_open_file():
    yield run_test_multi_open_file

if __name__ == "__main__":
    run_test_multi_open_file()
