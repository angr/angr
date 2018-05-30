import nose

import claripy

import angr
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeChar
from angr.utils.library import convert_cproto_to_py


def test_type_annotation():
    my_ty = angr.sim_type.SimTypeTop()
    ptr = claripy.BVS('ptr', 32).annotate(angr.type_backend.TypeAnnotation(angr.sim_type.SimTypePointer(my_ty, label=[])))
    ptroffset = ptr + 4

    bt = angr.type_backend.TypeBackend()
    tv = bt.convert(ptroffset)
    nose.tools.assert_is(tv.ty.pts_to, my_ty)
    nose.tools.assert_true(claripy.is_true(tv.ty.offset == 4))


def test_cproto_conversion():

    # A normal function declaration
    cproto_0 = "int main(int argc, char** argv);"
    pyproto_name, pyproto, the_str = convert_cproto_to_py(cproto_0)

    nose.tools.assert_equal(pyproto_name, "main")
    nose.tools.assert_is_instance(pyproto, SimTypeFunction)
    nose.tools.assert_is_instance(pyproto.args[0], SimTypeInt)
    nose.tools.assert_is_instance(pyproto.args[1], SimTypePointer)
    nose.tools.assert_is_instance(pyproto.args[1].pts_to.pts_to, SimTypeChar)
    nose.tools.assert_is_instance(pyproto.returnty, SimTypeInt)

    # Directly comparing the strings... how bad can I be?
    nose.tools.assert_equal(the_str,
                            '# int main(int argc, char** argv);\n"main": SimTypeFunction([SimTypeInt(signed=True, label=None), SimTypePointer(SimTypePointer(SimTypeChar(label=None), label=None, offset=0), label=None, offset=0)], SimTypeInt(signed=True, label=None), label=None),')

    # A bad function declaration
    cproto_1 = "int bad(xxxxxxx);"
    pyproto_name, pyproto, the_str = convert_cproto_to_py(cproto_1)  # pylint:disable=unused-variable

    nose.tools.assert_equal(pyproto_name, "bad")
    nose.tools.assert_is(pyproto, None)

    # A even worse function declaration
    # Special thanks to @schieb, see GitHub PR #958
    cproto_2 = "__attribute__ ((something)) void foo(void);"
    pyproto_name, pyproto, the_str = convert_cproto_to_py(cproto_2)  # pylint:disable=unused-variable

    nose.tools.assert_equal(pyproto_name, "foo")


if __name__ == '__main__':
    test_type_annotation()
    test_cproto_conversion()
