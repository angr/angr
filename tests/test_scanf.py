import nose

import logging
l = logging.getLogger('angr.tests.scanf')

import os
import string

import angr

test_location = str(os.path.dirname(os.path.realpath(__file__)))

class Checker(object):
    def __init__(self, check_func, length=None, base=10, dummy=False):
        self._check_func = check_func
        self._length = length
        self._base = base
        self._dummy = dummy

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
                if c in charset and s[i:i+2] not in ("0x", "0X"):
                    digit_start_pos = c

        if not component:
            component = s

        return component

    def check(self, path):
        if self._dummy:
            return True

        stdin_input = path.posix.files[0].content.load(1, 10) # skip the first char used in switch
        some_strings = path.se.any_n_str(stdin_input, 1000)

        for s in some_strings:

            if self._length is not None:
                s = s[ : self._length]

            component = self._extract_integer(s)

            if not self._check_func(component):
                return False

        return True

def run_scanf(threads):
    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/scanf_test")
    b = angr.Project(test_bin)

    pg = b.factory.simgr(immutable=False, threads=threads)

    # find the end of main
    expected_outputs = {
        "%%07x\n":                      Checker(lambda s: int(s, 16) == 0xaaaa, length=7, base=16),
        "%%07x and negative numbers\n": Checker(lambda s: int(s, 16) == -0xcdcd, length=7, base=16),
        "nope 0\n":                     Checker(None, dummy=True),
        "%%d\n":                        Checker(lambda s: int(s) == 133337),
        "%%d and negative numbers\n":   Checker(lambda s: int(s) == -1337),
        "nope 1\n":                     Checker(None, dummy=True),
        "%%u\n":                        Checker(lambda s: int(s) == 0xaaaa),
        "%%u and negative numbers\n":   Checker(lambda s: int(s) == -0xcdcd),
        "nope 2\n":                     Checker(None, dummy=True),
        "Unsupported switch\n":         Checker(None, dummy=True),
    }
    pg.explore(find=0x4007f3, num_find=len(expected_outputs))

    # check the outputs
    total_outputs = 0
    for path in pg.found:
        test_output = path.posix.dumps(1)
        if test_output in expected_outputs:
            nose.tools.assert_true(expected_outputs[test_output].check(path),
                                   "Test case failed. Output is %s." % test_output)

        total_outputs += 1

    # check that all of the outputs were seen
    nose.tools.assert_equal(total_outputs, len(expected_outputs))

def test_scanf():
    yield run_scanf, None
    # yield run_scanf, 8

if __name__ == "__main__":
    run_scanf(1)
