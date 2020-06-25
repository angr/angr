# pylint:disable=unused-variable
import nose

import claripy

import angr
from angr.sim_type import (SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeChar, SimStruct, SimTypeFloat, SimUnion,
                           SimTypeDouble, SimTypeLongLong, SimTypeLong, SimTypeNum, SimTypeReference, SimTypeBottom,
                           SimTypeString)
from angr.utils.library import convert_cproto_to_py, convert_cppproto_to_py


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
                            '# int main(int argc, char** argv);\n"main": SimTypeFunction([SimTypeInt(signed=True), SimTypePointer(SimTypePointer(SimTypeChar(), offset=0), offset=0)], SimTypeInt(signed=True), arg_names=["argc", "argv"]),')

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


def test_cppproto_conversion():

    # a demangled class constructor prototype, without parameter names
    proto_0 = "std::basic_ifstream<char, std::char_traits<char>>::{ctor}(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&, std::_Ios_Openmode)"
    name, proto, s = convert_cppproto_to_py(proto_0, with_param_names=False)
    assert proto.ctor is True
    assert name == "std::basic_ifstream::__ctor__"
    assert len(proto.args) == 3
    assert isinstance(proto.args[0], SimTypePointer)  # this
    assert isinstance(proto.args[1], SimTypeReference)
    assert isinstance(proto.args[1].refs, SimTypeString)
    assert proto.args[1].refs.name == "std::__cxx11::basic_string"
    assert proto.args[1].refs.unqualified_name(lang="c++") == "basic_string"

    proto_1 = "void std::basic_string<CharT,Traits,Allocator>::push_back(CharT ch)"
    name, proto, s = convert_cppproto_to_py(proto_1, with_param_names=True)
    assert name == "std::basic_string::push_back"
    assert isinstance(proto.returnty, SimTypeBottom)
    assert isinstance(proto.args[0], SimTypePointer)  # this
    assert isinstance(proto.args[1], SimTypeChar)

    proto_2 = "void std::basic_string<CharT,Traits,Allocator>::swap(basic_string& other)"
    name, proto, s = convert_cppproto_to_py(proto_2, with_param_names=True)
    assert name == "std::basic_string::swap"
    assert isinstance(proto.returnty, SimTypeBottom)
    assert isinstance(proto.args[0], SimTypePointer)  # this
    assert isinstance(proto.args[1], SimTypeReference)
    assert isinstance(proto.args[1].refs, SimTypeString)

    proto_3 = "std::ios_base::{base dtor}()"
    name, proto, s = convert_cppproto_to_py(proto_3, with_param_names=True)
    assert name == "std::ios_base::__base_dtor__"
    assert proto.dtor is True
    assert isinstance(proto.returnty, SimTypeBottom)

    proto_4 = "std::ios_base::{base dtor}()"
    name, proto, s = convert_cppproto_to_py(proto_4, with_param_names=True)
    assert name == "std::ios_base::__base_dtor__"

    proto_5 = "void foo(int & bar);"
    name, proto, s = convert_cppproto_to_py(proto_5, with_param_names=True)
    assert name == "foo"
    # note that there is no "this" pointer
    assert isinstance(proto.args[0], SimTypeReference)
    assert isinstance(proto.args[0].refs, SimTypeInt)
    assert isinstance(proto.returnty, SimTypeBottom)


def test_struct_deduplication():
    angr.types.register_types(angr.types.parse_type('struct ahdr { int a ;}'))
    angr.types.register_types(angr.types.parse_type('struct bhdr { int b ;}'))
    angr.types.register_types(angr.types.parse_type('struct chdr { int c ;}'))
    dhdr = angr.types.parse_type('struct dhdr { struct ahdr a; struct bhdr b; struct chdr c;}')
    assert dhdr.fields['a'].fields

def test_parse_type():
    int_ptr = angr.types.parse_type('int *')
    nose.tools.assert_is_instance(int_ptr, SimTypePointer)
    nose.tools.assert_is_instance(int_ptr.pts_to, SimTypeInt)

    char_ptr = angr.types.parse_type('char *c')
    nose.tools.assert_is_instance(char_ptr, SimTypePointer)
    nose.tools.assert_is_instance(char_ptr.pts_to, SimTypeChar)

    struct_parse_type = angr.types.parse_type('struct parse_type { char c; float f; }')
    nose.tools.assert_is_instance(struct_parse_type, SimStruct)
    nose.tools.assert_equal(struct_parse_type.name, 'parse_type')
    nose.tools.assert_equal(len(struct_parse_type.fields), 2)
    nose.tools.assert_is_instance(struct_parse_type.fields['c'], SimTypeChar)
    nose.tools.assert_is_instance(struct_parse_type.fields['f'], SimTypeFloat)

    union_dcba = angr.types.parse_type('union dcba { double d; long long int lli; }')
    nose.tools.assert_is_instance(union_dcba, SimUnion)
    nose.tools.assert_equal(union_dcba.name, 'dcba')
    nose.tools.assert_equal(len(union_dcba.members), 2)
    nose.tools.assert_is_instance(union_dcba.members['d'], SimTypeDouble)
    nose.tools.assert_is_instance(union_dcba.members['lli'], SimTypeLongLong)

    struct_llist = angr.types.parse_type('struct llist { int data; struct llist * next; }')
    nose.tools.assert_is_instance(struct_llist, SimStruct)
    nose.tools.assert_equal(struct_llist.name, 'llist')
    nose.tools.assert_equal(len(struct_llist.fields), 2)
    nose.tools.assert_is_instance(struct_llist.fields['data'], SimTypeInt)
    nose.tools.assert_is_instance(struct_llist.fields['next'], SimTypePointer)
    nose.tools.assert_is_instance(struct_llist.fields['next'].pts_to, SimStruct)
    nose.tools.assert_equal(struct_llist.fields['next'].pts_to.name, 'llist')

    func_ptr = angr.types.parse_type('double (*) (int, float)')
    nose.tools.assert_is_instance(func_ptr, SimTypePointer)
    nose.tools.assert_is_instance(func_ptr.pts_to, SimTypeFunction)
    nose.tools.assert_is_instance(func_ptr.pts_to.returnty, SimTypeDouble)
    nose.tools.assert_equal(len(func_ptr.pts_to.args), 2)
    nose.tools.assert_is_instance(func_ptr.pts_to.args[0], SimTypeInt)
    nose.tools.assert_is_instance(func_ptr.pts_to.args[1], SimTypeFloat)


def test_parse_type_no_basic_types():
    time_t = angr.types.parse_type('time_t')
    nose.tools.assert_is_instance(time_t, SimTypeLong)

    byte = angr.types.parse_type('byte')
    nose.tools.assert_is_instance(byte, SimTypeNum)
    nose.tools.assert_equal(byte.size, 8)
    nose.tools.assert_false(byte.signed)

def test_self_referential_struct_or_union():
    struct_llist = angr.types.parse_type('struct llist { int data; struct llist *next; }')
    next_struct_llist = struct_llist.fields['next'].pts_to
    nose.tools.assert_equal(len(next_struct_llist.fields), 2)
    nose.tools.assert_is_instance(next_struct_llist.fields['data'], SimTypeInt)
    nose.tools.assert_is_instance(next_struct_llist.fields['next'], SimTypePointer)

    union_heap = angr.types.parse_type('union heap { int data; union heap *forward; }')
    forward_union_heap = union_heap.members['forward'].pts_to
    nose.tools.assert_equal(len(forward_union_heap.members), 2)
    nose.tools.assert_is_instance(forward_union_heap.members['data'], SimTypeInt)
    nose.tools.assert_is_instance(forward_union_heap.members['forward'], SimTypePointer)

def test_union_struct_referencing_each_other():
    angr.types.register_types(angr.types.parse_type('struct a'))
    angr.types.register_types(angr.types.parse_type('struct b'))
    a = angr.types.parse_type('struct a { struct b *b_ptr; }')
    b = angr.types.parse_type('struct b { struct a *a_ptr; }')

    nose.tools.assert_equal(len(a.fields), 1)
    nose.tools.assert_is_instance(a.fields['b_ptr'], SimTypePointer)
    nose.tools.assert_is_instance(a.fields['b_ptr'].pts_to, SimStruct)
    nose.tools.assert_equal(a.fields['b_ptr'].pts_to.name, 'b')

    nose.tools.assert_equal(len(b.fields), 1)
    nose.tools.assert_is_instance(b.fields['a_ptr'], SimTypePointer)
    nose.tools.assert_is_instance(b.fields['a_ptr'].pts_to, SimStruct)
    nose.tools.assert_equal(b.fields['a_ptr'].pts_to.name, 'a')

    angr.types.register_types(angr.types.parse_type('union a'))
    angr.types.register_types(angr.types.parse_type('union b'))
    a = angr.types.parse_type('union a { union b *b_ptr; }')
    b = angr.types.parse_type('union b { union a *a_ptr; }')

    nose.tools.assert_equal(len(a.members), 1)
    nose.tools.assert_is_instance(a.members['b_ptr'], SimTypePointer)
    nose.tools.assert_is_instance(a.members['b_ptr'].pts_to, SimUnion)
    nose.tools.assert_equal(a.members['b_ptr'].pts_to.name, 'b')

    nose.tools.assert_equal(len(b.members), 1)
    nose.tools.assert_is_instance(b.members['a_ptr'], SimTypePointer)
    nose.tools.assert_is_instance(b.members['a_ptr'].pts_to, SimUnion)
    nose.tools.assert_equal(b.members['a_ptr'].pts_to.name, 'a')

def test_top_type():
    angr.types.register_types({'undefined': angr.types.SimTypeTop() })
    fdef = angr.types.parse_defns("undefined f(undefined param_1, int param_2);") # type: Dict[str, SimTypeFunction]
    sig = fdef['f']
    nose.tools.assert_equal(sig.args, [angr.types.SimTypeTop(), angr.types.SimTypeInt()])



def test_arg_names():
    angr.types.register_types({'undefined': angr.types.SimTypeTop() })
    fdef = angr.types.parse_defns("int f(int param_1, int param_2);") # type: Dict[str, SimTypeFunction]
    sig = fdef['f']
    nose.tools.assert_equal(sig.arg_names, ['param_1', 'param_2'])

    # Check that arg_names survive a with_arch call
    nsig = sig.with_arch(angr.archinfo.ArchAMD64())
    nose.tools.assert_equal(sig.arg_names, nsig.arg_names,
                            "Function type generated with .with_arch() doesn't have identical arg_names")

    # If for some reason only some of the parameters are named, the list can only be partially not None, but has to match the positions
    fdef = angr.types.parse_defns("int f(int param1, int);") # type: Dict[str, SimTypeFunction]
    sig = fdef['f']
    nose.tools.assert_equal(sig.arg_names, ['param1', None])

    fdef = angr.types.parse_defns("int f();") # type: Dict[str, SimTypeFunction]
    sig = fdef['f']
    nose.tools.assert_equal(sig.arg_names, ())

def test_varargs():
    fdef = angr.types.parse_defns("int printf(const char *fmt, ...);")
    sig = fdef['printf']

    nose.tools.assert_true(sig.variadic)
    nose.tools.assert_in('...', repr(sig))
    nose.tools.assert_equal(len(sig.args), 1)
    nose.tools.assert_equal(len(sig.arg_names), 1)
    nose.tools.assert_not_in('...', sig._init_str())


if __name__ == '__main__':
    test_type_annotation()
    test_cproto_conversion()
    test_cppproto_conversion()
    test_struct_deduplication()
    test_parse_type()
    test_parse_type_no_basic_types()
    test_self_referential_struct_or_union()
    test_union_struct_referencing_each_other()
    test_top_type()
    test_arg_names()
