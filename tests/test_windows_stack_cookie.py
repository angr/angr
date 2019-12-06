import os
import struct

import nose
import angr
import angr.simos.windows


test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '..', '..', 'binaries', 'tests')


def compare_none(state, test_value):
    test_value = test_value.concrete
    correct_value = angr.simos.windows.VS_SECURITY_COOKIES[state.arch.name].default
    nose.tools.assert_equal(test_value, correct_value)


def compare_random(state, test_value):
    test_value = test_value.concrete
    incorrect_value = angr.simos.windows.VS_SECURITY_COOKIES[state.arch.name].default
    nose.tools.assert_not_equal(test_value, incorrect_value)


def compare_static(state, test_value):
    test_value = test_value.concrete
    correct_value = struct.unpack('>I', b'cook')[0]
    nose.tools.assert_equal(test_value, correct_value)


def compare_symbolic(state, test_value):
    nose.tools.assert_true(test_value.resolved.symbolic)


def check_value(project, init_type, comparison):
    main_object = project.loader.main_object
    main_pe = main_object._pe
    load_config = main_pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct

    state = project.factory.blank_state(security_cookie_init=init_type)
    value = getattr(state.mem[load_config.SecurityCookie], "uint{0}_t".format(state.arch.bits))
    comparison(state, value)


def test_security_cookie_init():
    project = angr.Project(os.path.join(test_location, 'i386', 'test_arrays.exe'))
    check_value(project, angr.simos.windows.SecurityCookieInit.NONE, compare_none)
    check_value(project, angr.simos.windows.SecurityCookieInit.RANDOM, compare_random)
    check_value(project, angr.simos.windows.SecurityCookieInit.STATIC, compare_static)
    check_value(project, angr.simos.windows.SecurityCookieInit.SYMBOLIC, compare_symbolic)

    nose.tools.assert_raises(TypeError, project.factory.blank_state, security_cookie_init=1)


if __name__ == '__main__':
    test_security_cookie_init()
