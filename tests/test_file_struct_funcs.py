# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import logging
import unittest

import angr

l = logging.getLogger("angr.tests.test_file_struct_funcs")

test_location = os.path.dirname(os.path.realpath(__file__))


class TestFileStructFuncs(unittest.TestCase):
    def check_state_1(self, state):
        # Need to dump file.txt by path because program closes it
        return (
            state.posix.dump_file_by_path("file.txt") == b"testing abcdef"
            and state.posix.dumps(0)[:4] == b"xyz\n"
            and state.posix.dumps(1) == b"good1\n"
            and state.posix.dumps(2) == b""
        )

    def check_state_2(self, state):
        return (
            state.posix.dump_file_by_path("file.txt") == b"testing abcdef"
            and state.posix.dumps(0)[:4] == b"wxyz"
            and state.posix.dumps(1) == b""
            and state.posix.dumps(2) == b"good2\n"
        )

    def check_state_3(self, state):
        return (
            state.posix.dump_file_by_path("file.txt") == b"testing abcdef"
            and state.posix.dumps(1) == b""
            and state.posix.dumps(2) == b""
        )

    def test_file_struct_funcs(self):
        test_bin = os.path.join(test_location, "..", "..", "binaries", "tests", "x86_64", "file_func_test")
        b = angr.Project(test_bin, auto_load_libs=False)

        pg = b.factory.simulation_manager()
        pg.active[0].options.discard("LAZY_SOLVES")
        pg.explore()

        assert len(pg.deadended) == 3

        for p in pg.deadended:
            assert self.check_state_1(p) or self.check_state_2(p) or self.check_state_3(p)


if __name__ == "__main__":
    unittest.main()
