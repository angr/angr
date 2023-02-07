from typing import Dict

import archinfo

import angr
from angr.sim_type import (
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
    SimTypeChar,
    SimStruct,
    SimTypeFloat,
    SimUnion,
    SimTypeDouble,
    SimTypeLongLong,
    SimTypeLong,
    SimTypeNum,
    SimTypeReference,
    SimTypeBottom,
    SimTypeString,
)
from angr.utils.library import convert_cproto_to_py, convert_cppproto_to_py


def test_cproto_conversion():
    # A normal function declaration
    cproto_0 = "int main(int argc, char** argv);"
    pyproto_name, pyproto, the_str = convert_cproto_to_py(cproto_0)

    assert pyproto_name == "main"
    assert isinstance(pyproto, SimTypeFunction)
    assert isinstance(pyproto.args[0], SimTypeInt)
    assert isinstance(pyproto.args[1], SimTypePointer)
    assert isinstance(pyproto.args[1].pts_to.pts_to, SimTypeChar)
    assert isinstance(pyproto.returnty, SimTypeInt)

    # Directly comparing the strings... how bad can I be?
    assert the_str == (
        '# int main(int argc, char** argv);\n"main": SimTypeFunction([SimTypeInt(signed=True), SimTypePointer('
        'SimTypePointer(SimTypeChar(), offset=0), offset=0)], SimTypeInt(signed=True), arg_names=["argc", "argv"]),'
    )

    # A bad function declaration
    cproto_1 = "int bad(xxxxxxx);"
    pyproto_name, pyproto, the_str = convert_cproto_to_py(cproto_1)  # pylint:disable=unused-variable

    assert pyproto_name == "bad"
    assert pyproto is not None

    # A even worse function declaration
    # Special thanks to @schieb, see GitHub PR #958
    cproto_2 = "__attribute__ ((something)) void foo(void);"
    pyproto_name, pyproto, the_str = convert_cproto_to_py(cproto_2)  # pylint:disable=unused-variable

    assert pyproto_name == "foo"


def test_cppproto_conversion():
    # a demangled class constructor prototype, without parameter names
    proto_0 = (
        "std::basic_ifstream<char, std::char_traits<char>>::{ctor}(std::__cxx11::basic_string<char, "
        "std::char_traits<char>, std::allocator<char>> const&, std::_Ios_Openmode)"
    )
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
    angr.types.register_types(angr.types.parse_type("struct ahdr { int a ;}"))
    angr.types.register_types(angr.types.parse_type("struct bhdr { int b ;}"))
    angr.types.register_types(angr.types.parse_type("struct chdr { int c ;}"))
    dhdr = angr.types.parse_type("struct dhdr { struct ahdr a; struct bhdr b; struct chdr c;}")
    assert dhdr.fields["a"].fields


def test_parse_type():
    int_ptr = angr.types.parse_type("int *")
    assert isinstance(int_ptr, SimTypePointer)
    assert isinstance(int_ptr.pts_to, SimTypeInt)

    char_ptr = angr.types.parse_type("char *c")
    assert isinstance(char_ptr, SimTypePointer)
    assert isinstance(char_ptr.pts_to, SimTypeChar)

    struct_parse_type = angr.types.parse_type("struct parse_type { char c; float f; }")
    assert isinstance(struct_parse_type, SimStruct)
    assert struct_parse_type.name == "parse_type"
    assert len(struct_parse_type.fields) == 2
    assert isinstance(struct_parse_type.fields["c"], SimTypeChar)
    assert isinstance(struct_parse_type.fields["f"], SimTypeFloat)

    union_dcba = angr.types.parse_type("union dcba { double d; long long int lli; }")
    assert isinstance(union_dcba, SimUnion)
    assert union_dcba.name == "dcba"
    assert len(union_dcba.members) == 2
    assert isinstance(union_dcba.members["d"], SimTypeDouble)
    assert isinstance(union_dcba.members["lli"], SimTypeLongLong)

    struct_llist = angr.types.parse_type("struct llist { int data; struct llist * next; }")
    assert isinstance(struct_llist, SimStruct)
    assert struct_llist.name == "llist"
    assert len(struct_llist.fields) == 2
    assert isinstance(struct_llist.fields["data"], SimTypeInt)
    assert isinstance(struct_llist.fields["next"], SimTypePointer)
    assert isinstance(struct_llist.fields["next"].pts_to, SimStruct)
    assert struct_llist.fields["next"].pts_to.name == "llist"

    func_ptr = angr.types.parse_type("double (*) (int, float)")
    assert isinstance(func_ptr, SimTypePointer)
    assert isinstance(func_ptr.pts_to, SimTypeFunction)
    assert isinstance(func_ptr.pts_to.returnty, SimTypeDouble)
    assert len(func_ptr.pts_to.args) == 2
    assert isinstance(func_ptr.pts_to.args[0], SimTypeInt)
    assert isinstance(func_ptr.pts_to.args[1], SimTypeFloat)


def test_parse_type_no_basic_types():
    time_t = angr.types.parse_type("time_t")
    assert isinstance(time_t, SimTypeLong)

    byte = angr.types.parse_type("byte")
    assert isinstance(byte, SimTypeNum)
    assert byte.size == 8
    assert not byte.signed


def test_self_referential_struct_or_union():
    struct_llist = angr.types.parse_type("struct llist { int data; struct llist *next; }")
    next_struct_llist = struct_llist.fields["next"].pts_to
    assert len(next_struct_llist.fields) == 2
    assert isinstance(next_struct_llist.fields["data"], SimTypeInt)
    assert isinstance(next_struct_llist.fields["next"], SimTypePointer)

    union_heap = angr.types.parse_type("union heap { int data; union heap *forward; }")
    forward_union_heap = union_heap.members["forward"].pts_to
    assert len(forward_union_heap.members) == 2
    assert isinstance(forward_union_heap.members["data"], SimTypeInt)
    assert isinstance(forward_union_heap.members["forward"], SimTypePointer)


def test_union_struct_referencing_each_other():
    angr.types.register_types(angr.types.parse_type("struct a"))
    angr.types.register_types(angr.types.parse_type("struct b"))
    a = angr.types.parse_type("struct a { struct b *b_ptr; }")
    b = angr.types.parse_type("struct b { struct a *a_ptr; }")

    assert len(a.fields) == 1
    assert isinstance(a.fields["b_ptr"], SimTypePointer)
    assert isinstance(a.fields["b_ptr"].pts_to, SimStruct)
    assert a.fields["b_ptr"].pts_to.name == "b"

    assert len(b.fields) == 1
    assert isinstance(b.fields["a_ptr"], SimTypePointer)
    assert isinstance(b.fields["a_ptr"].pts_to, SimStruct)
    assert b.fields["a_ptr"].pts_to.name == "a"

    angr.types.register_types(angr.types.parse_type("union a"))
    angr.types.register_types(angr.types.parse_type("union b"))
    a = angr.types.parse_type("union a { union b *b_ptr; }")
    b = angr.types.parse_type("union b { union a *a_ptr; }")

    assert len(a.members) == 1
    assert isinstance(a.members["b_ptr"], SimTypePointer)
    assert isinstance(a.members["b_ptr"].pts_to, SimUnion)
    assert a.members["b_ptr"].pts_to.name == "b"

    assert len(b.members) == 1
    assert isinstance(b.members["a_ptr"], SimTypePointer)
    assert isinstance(b.members["a_ptr"].pts_to, SimUnion)
    assert b.members["a_ptr"].pts_to.name == "a"


def test_top_type():
    angr.types.register_types({"undefined": angr.types.SimTypeTop()})
    fdef: Dict[str, SimTypeFunction] = angr.types.parse_defns("undefined f(undefined param_1, int param_2);")
    sig = fdef["f"]
    assert sig.args == [angr.types.SimTypeTop(), angr.types.SimTypeInt()]


def test_arg_names():
    angr.types.register_types({"undefined": angr.types.SimTypeTop()})
    fdef: Dict[str, SimTypeFunction] = angr.types.parse_defns("int f(int param_1, int param_2);")
    sig = fdef["f"]
    assert sig.arg_names == ["param_1", "param_2"]

    # Check that arg_names survive a with_arch call
    nsig = sig.with_arch(angr.archinfo.ArchAMD64())
    assert sig.arg_names == nsig.arg_names, "Function type generated with .with_arch() doesn't have identical arg_names"

    # If for some reason only some of the parameters are named,
    # the list can only be partially not None, but has to match the positions
    fdef: Dict[str, SimTypeFunction] = angr.types.parse_defns("int f(int param1, int);")
    sig = fdef["f"]
    assert sig.arg_names == ["param1", None]

    fdef: Dict[str, SimTypeFunction] = angr.types.parse_defns("int f();")
    sig = fdef["f"]
    assert sig.arg_names == ()


def test_varargs():
    fdef = angr.types.parse_defns("int printf(const char *fmt, ...);")
    sig = fdef["printf"]

    assert sig.variadic
    assert "..." in repr(sig)
    assert len(sig.args) == 1
    assert len(sig.arg_names) == 1
    assert "..." not in sig._init_str()


def test_forward_declaration_typedef_struct():
    types, extra_types = angr.types.parse_file("typedef struct _A A; struct _A {int a;int b;};")

    assert extra_types["A"].fields is not None
    assert isinstance(extra_types["A"].fields["a"], SimTypeInt)
    assert isinstance(extra_types["A"].fields["b"], SimTypeInt)

    assert extra_types["struct _A"].fields is not None
    assert isinstance(extra_types["struct _A"].fields["a"], SimTypeInt)
    assert isinstance(extra_types["struct _A"].fields["b"], SimTypeInt)


def test_forward_declaration_typedef_union():
    types, extra_types = angr.types.parse_file("typedef union _A A; union _A {int a;int b;};")

    assert extra_types["A"].members is not None
    assert isinstance(extra_types["A"].members["a"], SimTypeInt)
    assert isinstance(extra_types["A"].members["b"], SimTypeInt)

    assert extra_types["union _A"].members is not None
    assert isinstance(extra_types["union _A"].members["a"], SimTypeInt)
    assert isinstance(extra_types["union _A"].members["b"], SimTypeInt)


def test_bitfield_struct():
    code = """
    struct bitfield_struct {
        uint64_t    qword;
        uint64_t    a    : 36,
                    b     :  8,
                    c  :  7,
                    d      : 12,
                    e      :  1;
        char*       name;
    }"""
    ty = angr.types.parse_type(code)
    ty = ty.with_arch(archinfo.ArchAArch64())
    assert [(t.size, t.offset) for t in list(ty.fields.values())[1:-1]] == [
        (36, 0),
        (8, 4),
        (7, 4),
        (12, 3),
        (1, 7),
    ]


if __name__ == "__main__":
    test_cproto_conversion()
    test_cppproto_conversion()
    test_struct_deduplication()
    test_parse_type()
    test_parse_type_no_basic_types()
    test_self_referential_struct_or_union()
    test_union_struct_referencing_each_other()
    test_top_type()
    test_arg_names()
    test_forward_declaration_typedef_struct()
    test_forward_declaration_typedef_union()
    test_bitfield_struct()
