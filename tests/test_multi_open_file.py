import nose
import angr
import os

import logging
l = logging.getLogger('angr.tests.test_multi_open_file')

test_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_multi_open_file():
    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/test_multi_open_file")
    b = angr.Project(test_bin)

    pg = b.factory.simulation_manager()
    pg.active[0].options.discard("LAZY_SOLVES")
    pg.explore()

    nose.tools.assert_equal(len(pg.deadended), 1)

    # See the source file in binaries/tests_src/test_multi_open_file.c
    # for the tests run
    for p in pg.deadended:
        nose.tools.assert_true(p.posix.dumps(2) == b"")

        # Check that the temp file was deleted
        nose.tools.assert_equal(p.fs._files, {})

        # Check that the deleted temp file contained the appropriate string
        for event in p.history.events:
            if event.type == 'fs_unlink':
                simfile = p.fs.unlinks[event.objects['unlink_idx']][1]
                nose.tools.assert_equal(simfile.concretize(), b'foobar and baz')
                break
        else:
            assert False


if __name__ == "__main__":
    test_multi_open_file()
