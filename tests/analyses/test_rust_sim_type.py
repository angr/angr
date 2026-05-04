from __future__ import annotations

from collections import OrderedDict

import archinfo

from angr.rust.sim_type import (
    EnumVariant,
    RustSimEnum,
    RustSimStruct,
    RustSimTypeArray,
    RustSimTypeBottom,
    RustSimTypeFunction,
    RustSimTypeInt,
    RustSimTypeOption,
    RustSimTypeReference,
    RustSimTypeResult,
    RustSimTypeSize,
    RustSimTypeSlice,
    RustSimTypeStrRef,
    RustSimTypeUnit,
    RustSimTypeVec,
    is_composite_type,
)


def test_rust_retbuf_function_normalization():
    arch = archinfo.ArchAMD64()
    field_ty = RustSimTypeInt(64, signed=False).with_arch(arch)
    ret_ty = RustSimStruct(OrderedDict({"field_0": field_ty}), name="Ret", pack=True).with_arch(arch)
    prototype = RustSimTypeFunction(
        [RustSimTypeReference(ret_ty).with_arch(arch), field_ty],
        None,
        is_arg0_retbuf=True,
    ).with_arch(arch)

    normalized = prototype.normalize()

    assert is_composite_type(ret_ty)
    assert normalized.returnty is ret_ty
    assert tuple(normalized.args) == (field_ty,)
    assert normalized.is_arg0_retbuf is False
    assert prototype.normalize() is not prototype


def test_rust_scalar_reference_and_array_repr_json_roundtrip():
    arch = archinfo.ArchAMD64()
    u32 = RustSimTypeInt(32, signed=False, label="len").with_arch(arch)

    assert repr(u32) == "u32"
    assert u32.repr("n") == "n: u32"
    assert RustSimTypeInt.from_json(u32.to_json()).label == "len"

    usize = RustSimTypeSize(signed=False).with_arch(arch)
    assert usize.size == 64
    assert repr(usize) == "usize"
    assert RustSimTypeSize.from_json(usize.to_json()).signed is False
    assert usize.copy().size == 64

    bottom_ref = RustSimTypeReference(RustSimTypeBottom())
    assert bottom_ref.repr("ptr") == "*u8 ptr"

    ref = RustSimTypeReference(u32, label="r", offset=4).with_arch(arch)
    assert ref.size == 64
    assert ref.repr("arg") == "arg: &u32"
    assert ref.copy().offset == 4

    array = RustSimTypeArray(u32, length=3, label="arr").with_arch(arch)
    assert repr(array) == "[u32; 3]"
    assert array.repr("items") == "items: [u32; 3]"
    assert array.copy().length == 3

    fn = RustSimTypeFunction([ref, u32], u32, arg_names=["self", "n"], variadic=True).with_arch(arch)
    assert "..." in repr(fn)
    assert "..." in fn._repr("callee", full=1)
    assert '"self"' in fn._arg_names_str()
    assert fn.to_json()["variadic"] is True


def test_rust_struct_nested_field_lookup_and_json_roundtrip():
    arch = archinfo.ArchAMD64()
    inner = RustSimStruct(
        OrderedDict({"value": RustSimTypeInt(16, signed=False)}), name="Inner", pack=True
    ).with_arch(arch)
    outer = RustSimStruct(
        OrderedDict({"inner": inner, "tail": RustSimTypeInt(32, signed=False)}), name="Outer", pack=True
    ).with_arch(arch)

    assert outer.get_field_ty("inner.value").size == 16
    assert outer.get_field_offset("inner.value") == 0
    assert outer.get_field_offset("missing", default=-1) == -1
    assert "struct Outer" in outer.repr(full=2)

    data = outer.to_json()
    data["_size"] = outer.size
    restored = RustSimStruct.from_json(data)
    assert restored.name == "Outer"
    assert restored._size == outer.size


def test_rust_enum_result_option_discriminants_and_json_roundtrip():
    arch = archinfo.ArchAMD64()
    ok_ty = RustSimTypeInt(64, signed=False)
    err_ty = RustSimTypeInt(16, signed=False)

    result_ty = RustSimTypeResult(ok_ty, 0, 0, err_ty, -(1 << 15), 2).with_arch(arch)
    assert result_ty.get_variant(1 << 15).name == "Err"
    assert RustSimTypeResult.from_json(result_ty.to_json()).name.startswith("Result<")

    option_ty = RustSimTypeOption(0, 1, ok_ty, 1, 1).with_arch(arch)
    assert option_ty.get_variant(0).name == "None"
    assert RustSimTypeOption.from_json(option_ty.to_json()).name.startswith("Option<")

    none = EnumVariant.from_no_data("None", 0, 1)
    some = EnumVariant.from_single_field_ty("Some", ok_ty, 1, 1)
    enum_ty = RustSimEnum("OptionLike", [none, some]).with_arch(arch)
    assert enum_ty.get_variant_by_name("Some").name == "Some"
    assert enum_ty.num_variants() == 2
    assert RustSimEnum.from_json(enum_ty.to_json()).name == "OptionLike"

    some_with_arch = some.with_arch(arch)
    assert some_with_arch.has_fields()
    assert some_with_arch.first_field_offset >= 1
    assert some_with_arch.size == some_with_arch.bits // 8
    assert some_with_arch.as_struct_ty().fields["discriminant"].size == 8
    assert EnumVariant.from_json(some_with_arch.to_json()) == some


def test_rust_slice_layout_uses_two_machine_words():
    arch = archinfo.ArchAMD64()
    slice_ty = RustSimTypeSlice(RustSimTypeInt(8, signed=False)).with_arch(arch)

    assert slice_ty.size == 128
    assert list(slice_ty.fields) == ["data_ptr", "length"]
    assert slice_ty.repr("s") == "s: &[u8]"

    vec_ty = RustSimTypeVec(RustSimTypeInt(16, signed=False), order=("ptr", "len", "cap")).with_arch(arch)
    assert repr(vec_ty) == "Vec<u16>"
    assert list(vec_ty.fields) == ["ptr", "len", "cap"]
    assert RustSimTypeVec.from_json(vec_ty.to_json()).order == ("ptr", "len", "cap")

    unit_ty = RustSimTypeUnit().with_arch(arch)
    assert unit_ty.size == 0
    assert unit_ty.copy().name == "()"
    assert RustSimTypeUnit.from_json(unit_ty.to_json()).name == "()"

    strref_ty = RustSimTypeStrRef().with_arch(arch)
    assert repr(strref_ty) == "&str"
    assert strref_ty.copy().name == "&str"
    assert RustSimTypeStrRef.from_json(strref_ty.to_json()).name == "&str"
