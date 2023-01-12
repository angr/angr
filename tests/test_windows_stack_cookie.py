import os
import struct
import unittest

import angr
import angr.simos.windows

test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), "..", "..", "binaries", "tests")


def compare_none(state, test_value):
    test_value = test_value.concrete
    correct_value = angr.simos.windows.VS_SECURITY_COOKIES[state.arch.name].default
    assert test_value == correct_value


def compare_random(state, test_value):
    test_value = test_value.concrete
    incorrect_value = angr.simos.windows.VS_SECURITY_COOKIES[state.arch.name].default
    assert test_value != incorrect_value


def compare_static(state, test_value):
    test_value = test_value.concrete
    correct_value = struct.unpack(">I", b"cook")[0]
    assert test_value == correct_value


def compare_symbolic(state, test_value):
    assert test_value.resolved.symbolic


def check_value(project, init_type, comparison):
    main_object = project.loader.main_object
    state = project.factory.blank_state(security_cookie_init=init_type)
    value = getattr(state.mem[main_object.load_config["SecurityCookie"]], f"uint{state.arch.bits}_t")
    comparison(state, value)


class TestWindowsStackCookie(unittest.TestCase):
    def test_security_cookie_init(self):
        project = angr.Project(os.path.join(test_location, "i386", "test_arrays.exe"), auto_load_libs=False)
        check_value(project, angr.simos.windows.SecurityCookieInit.NONE, compare_none)
        check_value(project, angr.simos.windows.SecurityCookieInit.RANDOM, compare_random)
        check_value(project, angr.simos.windows.SecurityCookieInit.STATIC, compare_static)
        check_value(project, angr.simos.windows.SecurityCookieInit.SYMBOLIC, compare_symbolic)

        self.assertRaises(TypeError, project.factory.blank_state, security_cookie_init=1)


if __name__ == "__main__":
    unittest.main()
