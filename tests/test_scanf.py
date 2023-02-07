import os
import string
import logging

import unittest

import angr
import claripy

l = logging.getLogger("angr.tests.scanf")
test_location = os.path.dirname(os.path.realpath(__file__))


class Checker:
    def __init__(
        self, check_func, length=None, base=10, dummy: bool = False, multi: bool = False, delimiter: str = None
    ):
        self._check_func = check_func
        self._length = length
        self._base = base
        self._dummy = dummy
        self._multi = multi
        self._delimiter = delimiter

        if multi:
            if not delimiter:
                raise ValueError("Delimiter is required when multi is True.")
            if not isinstance(check_func, list):
                raise TypeError("You must provide a list of check functions when multi is True.")
            self._parts = len(check_func)

    def _extract_integer(self, s):
        charset = string.digits if self._base == 10 else string.digits + "abcdefABCDEF"

        component = ""

        digit_start_pos = None

        for i, c in enumerate(s):
            if digit_start_pos is not None:
                if c not in charset:
                    component = s[:i]
                    break
            else:
                if c in charset and s[i : i + 2] not in ("0x", "0X"):
                    digit_start_pos = c

        if not component:
            component = s

        return component

    def check(self, path):
        if self._dummy:
            return True

        if not isinstance(path.posix.stdin, angr.storage.file.SimPacketsStream):
            raise TypeError("This test case only supports SimPacketsStream-type of stdin.")

        if not self._multi:
            stdin_input = path.posix.stdin.content[1][0]  # skip the first char used in switch
        else:
            stdin_input = claripy.Concat(*[part[0] for part in path.posix.stdin.content[1:]])
        some_strings = path.solver.eval_upto(stdin_input, 1000, cast_to=bytes)
        some_strings = [x.decode() for x in some_strings]

        check_passes = False

        for s in some_strings:
            if self._length is not None:
                s = s[: self._length]

            if not self._multi:
                # single part
                component = self._extract_integer(s)
                if self._check_func(component):
                    check_passes = True
                    break
            else:
                # multiple parts
                substrs = s.split(self._delimiter)
                if len(substrs) != len(self._check_func):
                    continue

                components = [self._extract_integer(substr) for substr in substrs]

                if all(func(component) for func, component in zip(self._check_func, components)):
                    check_passes = True
                    break

        return check_passes


class TestScanf(unittest.TestCase):
    def test_scanf(self):
        test_bin = os.path.join(test_location, "..", "..", "binaries", "tests", "x86_64", "scanf_test")
        b = angr.Project(test_bin, auto_load_libs=False)

        pg = b.factory.simulation_manager()

        # find the end of main
        expected_outputs = {
            b"%%07x\n": Checker(lambda s: int(s, 16) == 0xAAAA, length=7, base=16),
            b"%%07x and negative numbers\n": Checker(lambda s: int(s, 16) == -0xCDCD, length=7, base=16),
            b"nope 0\n": Checker(None, dummy=True),
            b"%%d\n": Checker(lambda s: int(s) == 133337),
            b"%%d and negative numbers\n": Checker(lambda s: int(s) == 2**32 - 1337),
            b"nope 1\n": Checker(None, dummy=True),
            b"%%u\n": Checker(lambda s: int(s) == 0xAAAA),
            b"%%u and negative numbers\n": Checker(lambda s: int(s) == 2**32 - 0xCDCD),
            b"nope 2\n": Checker(None, dummy=True),
            b"Unsupported switch\n": Checker(None, dummy=True),
        }
        pg.explore(find=0x4007F3, num_find=len(expected_outputs))

        # check the outputs
        total_outputs = 0
        for path in pg.found:
            test_output = path.posix.dumps(1)
            if test_output in expected_outputs:
                assert expected_outputs[test_output].check(path), "Test case failed. Output is %s." % test_output

            total_outputs += 1

        # check that all of the outputs were seen
        assert total_outputs == len(expected_outputs)

    def test_scanf_multi(self):
        test_bin = os.path.join(test_location, "..", "..", "binaries", "tests", "x86_64", "scanf_multi_test")
        b = angr.Project(test_bin, auto_load_libs=False)

        pg = b.factory.simulation_manager()

        expected_outputs = {
            b"%%04x.%%04x.%%04x\n": Checker(
                [
                    lambda x: int(x, 16) == 0xAAAA,
                    lambda x: int(x, 16) == 0xBBBB,
                    lambda x: int(x, 16) == 0xCCCC,
                ],
                base=16,
                multi=True,
                delimiter=".",
            ),
            b"%%04x.%%04x.%%04x and negative numbers\n": Checker(
                [lambda x: int(x, 16) == -0xCD] * 3,
                base=16,
                multi=True,
                delimiter=".",
            ),
            b"%%d.%%d.%%d\n": Checker(
                [lambda x: int(x, 10) == 133337, lambda x: int(x, 10) == 1337, lambda x: int(x, 10) == 13337],
                base=10,
                multi=True,
                delimiter=".",
            ),
            b"%%d.%%d.%%d and negative numbers\n": Checker(
                [lambda x: int(x, 10) == 2**32 - 1337] * 3,
                base=10,
                multi=True,
                delimiter=".",
            ),
            b"%%u\n": Checker(
                [lambda x: int(x) == 0xAAAA, lambda x: int(x) == 0xBBBB, lambda x: int(x) == 0xCCCC],
                base=10,
                multi=True,
                delimiter=".",
            ),
            b"%%u and negative numbers\n": Checker(
                [lambda s: int(s) == 2**32 - 0xCDCD] * 3,
                base=10,
                multi=True,
                delimiter=".",
            ),
            b"Unsupported switch\n": Checker(None, dummy=True),
        }
        pg.explore(
            find=0x40083E,
            avoid=(
                0x4006DB,
                0x400776,
                0x40080B,
            ),  # avoid all "nope N" branches
            num_find=len(expected_outputs),
        )

        # check the outputs
        total_outputs = 0
        for path in pg.found:
            path.posix.dumps(0)
            test_output = path.posix.dumps(1)
            if test_output in expected_outputs:
                assert expected_outputs[test_output].check(path), "Test case failed. Output is %s." % test_output

            total_outputs += 1

        # check that all of the outputs were seen
        assert total_outputs == len(expected_outputs)


if __name__ == "__main__":
    unittest.main()
