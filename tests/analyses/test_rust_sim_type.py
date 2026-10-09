from __future__ import annotations

import json
import os
import unittest
from collections import OrderedDict

import archinfo

import angr
import angr.rust.knowledge_plugins  # pylint:disable=unused-import
from angr.analyses.typehoon import typeconsts
from angr.knowledge_plugins.functions.function_parser import FunctionParser
from angr.rust.analyses.type_db_loader import TypeDBLoader
from angr.rust.sim_type import (
    ANON_STRUCT_NAME,
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
from angr.rust.typehoon.translator import RustTypeTranslator
from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeFunction,
    SimTypeLongLong,
    SimTypePointer,
    SimTypeRef,
    TypeRef,
)
from tests.common import bin_location


def _blank_type_db_loader() -> TypeDBLoader:
    project = angr.load_shellcode(b"\x90", arch="amd64")
    loader = object.__new__(TypeDBLoader)
    loader.project = project
    loader.kb = project.kb
    loader._struct_db = {}
    loader._prototype_db = {}
    loader._pending_types = set()
    return loader


class TestRustSimType(unittest.TestCase):
    def test_with_arch_never_strips_an_existing_arch(self):
        # Function.prototype's setter copies arch-less prototypes, and copy() ends in with_arch(self._arch);
        # rebuilding there instead of returning self strips the arch off every argument
        arch = archinfo.ArchAMD64()
        u64 = RustSimTypeInt(64, signed=False).with_arch(arch)
        ok_ty = RustSimStruct(OrderedDict({"field_0": u64}), name="struct8", pack=True).with_arch(arch)
        err_ty = RustSimStruct(OrderedDict({"field_0": u64}), name="struct16", pack=True).with_arch(arch)
        ref = RustSimTypeReference(RustSimTypeResult(ok_ty, 0, 8, err_ty, 1, 8).with_arch(arch)).with_arch(arch)

        assert ref.with_arch(None) is ref
        assert ref.with_arch(arch) is ref

        prototype = RustSimTypeFunction([ref, u64], None, is_arg0_retbuf=True)
        assert prototype._arch is None
        assert prototype.copy().args[0]._arch == arch

        # every type entering the type solver has to carry an arch
        RustTypeTranslator(arch).simtype2tc(prototype.copy().args[0])

    def test_rust_retbuf_function_normalization(self):
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
        assert normalized.returnty == ret_ty
        assert tuple(normalized.args) == (field_ty,)
        assert normalized.is_arg0_retbuf is False
        assert prototype.normalize() is not prototype

    def test_rust_scalar_reference_and_array_repr_json_roundtrip(self):
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

    def test_rust_int_equality_includes_size(self):
        # regression test for angr/angr#6625: ints of different sizes compared equal (and hashed equal), which made
        # the declared type of unified variables depend on nondeterministic set iteration order
        u8 = RustSimTypeInt(8, signed=False)
        u32 = RustSimTypeInt(32, signed=False)
        u64 = RustSimTypeInt(64, signed=False)

        assert u32 != u64
        assert u8 != u32
        assert hash(u32) != hash(u64)
        assert u32 == RustSimTypeInt(32, signed=False)
        assert hash(u32) == hash(RustSimTypeInt(32, signed=False))
        assert u32 != RustSimTypeInt(32, signed=True)

        # copy() must preserve the explicit size
        assert u64.copy().size == 64
        assert u64.copy() == u64

    def test_rust_struct_nested_field_lookup_and_json_roundtrip(self):
        arch = archinfo.ArchAMD64()
        inner = RustSimStruct(
            OrderedDict({"value": RustSimTypeInt(16, signed=False)}), name="Inner", pack=True
        ).with_arch(arch)
        outer = RustSimStruct(
            OrderedDict({"inner": inner, "tail": RustSimTypeInt(32, signed=False)}), name="Outer", pack=True
        ).with_arch(arch)

        inner_value_ty = outer.get_field_ty("inner.value")
        assert inner_value_ty is not None
        assert inner_value_ty.size == 16
        assert outer.get_field_offset("inner.value") == 0
        assert outer.get_field_offset("missing", default=-1) == -1
        assert "struct Outer" in outer.repr(full=2)

        data = outer.to_json()
        data["_size"] = outer.size
        restored = RustSimStruct.from_json(data)
        assert restored.name == "Outer"
        assert restored._size == outer.size

    def test_rust_enum_result_option_discriminants_and_json_roundtrip(self):
        arch = archinfo.ArchAMD64()
        ok_ty = RustSimTypeInt(64, signed=False)
        err_ty = RustSimTypeInt(16, signed=False)

        result_ty = RustSimTypeResult(ok_ty, 0, 0, err_ty, -(1 << 15), 2).with_arch(arch)
        err_variant = result_ty.get_variant(1 << 15)
        assert err_variant is not None
        assert err_variant.name == "Err"
        assert RustSimTypeResult.from_json(result_ty.to_json()).name.startswith("Result<")

        option_ty = RustSimTypeOption(0, 1, ok_ty, 1, 1).with_arch(arch)
        none_variant = option_ty.get_variant(0)
        assert none_variant is not None
        assert none_variant.name == "None"
        assert RustSimTypeOption.from_json(option_ty.to_json()).name.startswith("Option<")

        none = EnumVariant.from_no_data("None", 0, 1)
        some = EnumVariant.from_single_field_ty("Some", ok_ty, 1, 1)
        enum_ty = RustSimEnum("OptionLike", [none, some]).with_arch(arch)
        some_variant = enum_ty.get_variant_by_name("Some")
        assert some_variant is not None
        assert some_variant.name == "Some"
        assert enum_ty.num_variants() == 2
        assert RustSimEnum.from_json(enum_ty.to_json()).name == "OptionLike"

        some_with_arch = some.with_arch(arch)
        assert some_with_arch.has_fields()
        assert some_with_arch.first_field_offset >= 1
        assert some_with_arch.size == some_with_arch.bits // 8
        assert some_with_arch.as_struct_ty().fields["discriminant"].size == 8
        assert EnumVariant.from_json(some_with_arch.to_json()) == some

    def test_rust_recursive_types_json_roundtrip(self):
        # Regression test for angr/angr#7137: to_json must break reference cycles through the memo like SimStruct does.
        node = RustSimStruct(OrderedDict(), name="struct_0")
        node.fields["next"] = SimTypePointer(TypeRef("struct_0", node))
        node.fields["val"] = RustSimTypeInt(64, signed=True)
        d = json.loads(json.dumps(node.to_json()))
        assert d["fields"]["next"]["pts_to"]["ty"] == {"_t": "_ref", "name": "struct_0", "ot": "rust_struct"}
        back = SimType.from_json(d)
        assert isinstance(back, RustSimStruct) and back.name == "struct_0"
        assert isinstance(back.fields["next"].pts_to.type, SimTypeRef)

        a = RustSimStruct(OrderedDict(), name="A")
        b = RustSimStruct(OrderedDict(), name="B")
        a.fields["b"] = SimTypePointer(TypeRef("B", b))
        b.fields["a"] = SimTypePointer(TypeRef("A", a))
        assert SimType.from_json(json.loads(json.dumps(a.to_json()))).name == "A"

        lst = RustSimEnum("List", [EnumVariant.from_no_data("Nil", 0, 8)])
        lst.variants.append(EnumVariant.from_single_field_ty("Cons", SimTypePointer(TypeRef("List", lst)), 1, 8))
        assert RustSimEnum.from_json(json.loads(json.dumps(lst.to_json()))).name == "List"

        holder = RustSimStruct(OrderedDict(), name="Node")
        holder.fields["next"] = RustSimTypeOption(0, 8, SimTypePointer(TypeRef("Node", holder)), 1, 8)
        assert SimType.from_json(json.loads(json.dumps(holder.to_json()))).name == "Node"
        ok = RustSimStruct(OrderedDict(), name="Tree")
        ok.fields["child"] = RustSimTypeResult(SimTypePointer(TypeRef("Tree", ok)), 0, 8, RustSimTypeInt(32), 1, 8)
        assert SimType.from_json(json.loads(json.dumps(ok.to_json()))).name == "Tree"

    def test_a_rust_enum_used_twice_survives_one_json_document(self):
        # to_json emits the enum once and a reference for every later use, which is what keeps the
        # document small. Nothing used to resolve that reference on the way back in:
        # SimType.from_json registered only structs and unions as reference targets, and a custom
        # from_json was called with no decode state at all.
        count = RustSimEnum(
            "core::fmt::rt::Count",
            [
                EnumVariant.from_no_data("Implied", 0, 8),
                EnumVariant.from_single_field_ty("Is", RustSimTypeSize(signed=False), 1, 8),
            ],
        )
        emitted = json.loads(json.dumps(SimTypeFunction([count, count], RustSimTypeInt(32)).to_json()))
        # the deduplication is the point of the memo and is unchanged
        assert emitted["args"][1] == {"_t": "_ref", "name": "core::fmt::rt::Count", "ot": "rust_enum"}
        restored = SimType.from_json(emitted)
        for argument in restored.args:
            assert isinstance(argument, RustSimEnum)
            assert [variant.name for variant in argument.variants] == ["Implied", "Is"]
        assert restored.args[0] is restored.args[1]

    def test_a_rust_struct_used_twice_survives_one_json_document(self):
        # the same defect through RustSimStruct, whose to_json shares the memo
        inner = RustSimStruct(OrderedDict([("a", RustSimTypeInt(32))]), name="Pair")
        emitted = json.loads(json.dumps(SimTypeFunction([inner, inner], RustSimTypeInt(32)).to_json()))
        assert emitted["args"][1] == {"_t": "_ref", "name": "Pair", "ot": "rust_struct"}
        restored = SimType.from_json(emitted)
        for argument in restored.args:
            assert isinstance(argument, RustSimStruct)
            assert list(argument.fields) == ["a"]
        assert restored.args[0] is restored.args[1]

    def test_two_nameless_rust_structs_under_one_parent_stay_distinct(self):
        # SimStruct names an unnamed struct "<anon>", so a shared with_arch memo keyed on the name
        # made the first anonymous struct answer for the second: the parent came back 64 bits wide
        # with both fields reading x, instead of 128 with x and y.
        left = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)))
        right = RustSimStruct(OrderedDict(y=RustSimTypeInt(64)))
        parent = RustSimStruct(OrderedDict(left=left, right=right), name="Holder").with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        arched_left, arched_right = parent.fields["left"], parent.fields["right"]
        assert isinstance(arched_left, RustSimStruct)
        assert isinstance(arched_right, RustSimStruct)
        assert list(arched_left.fields) == ["x"]
        assert list(arched_right.fields) == ["y"]
        assert arched_left is not arched_right
        assert parent.size == 128
        assert parent.offsets == {"left": 0, "right": 8}

    def test_a_nameless_rust_parent_does_not_collide_with_its_nameless_child(self):
        child = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)))
        source = RustSimStruct(OrderedDict(child=child), pack=True, align=16)
        source.anonymous = True
        source._size = 128
        parent = source.with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        arched_child = parent.fields["child"]
        assert isinstance(arched_child, RustSimStruct)
        assert arched_child is not parent
        assert list(arched_child.fields) == ["x"]
        assert parent.name == ANON_STRUCT_NAME
        self.assertTrue(parent.anonymous)
        self.assertFalse(arched_child.anonymous)
        self.assertTrue(parent._pack)
        self.assertEqual(parent._align, 16)
        self.assertEqual(parent.size, 128)

    def test_one_nameless_rust_struct_used_twice_is_converted_once(self):
        # the other half of the memo: the same object must still come back as one object, or a
        # recursive anonymous type would not terminate
        shared = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)))
        parent = RustSimStruct(OrderedDict(a=shared, b=shared), name="Holder").with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        assert parent.fields["a"] is parent.fields["b"]

    def test_an_enum_variants_nameless_wrapper_survives_with_arch(self):
        # EnumVariant.type builds a nameless RustSimStruct around the variant's fields; converting
        # it used to make both fields the wrapper itself, and reading size or offsets then recursed
        left = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)))
        right = RustSimStruct(OrderedDict(y=RustSimTypeInt(64)))
        wrapper = EnumVariant("HolderVariant", [(left, "left"), (right, "right")], 0, 0).type
        arched = wrapper.with_arch(archinfo.ArchAMD64())
        assert isinstance(arched, RustSimStruct)
        arched_left, arched_right = arched.fields["left"], arched.fields["right"]
        assert isinstance(arched_left, RustSimStruct)
        assert isinstance(arched_right, RustSimStruct)
        assert arched_left is not arched and arched_right is not arched
        assert list(arched_left.fields) == ["x"]
        assert list(arched_right.fields) == ["y"]
        assert arched.size == 128

    def test_two_vecs_of_nameless_rust_structs_stay_distinct(self):
        # RustSimTypeVec names itself out of the element's repr, so a vector of an unnamed struct is
        # called Vec<<anon>> whatever the element holds. Keying the with_arch memo on that made the
        # second vector come back as the first.
        left = RustSimTypeVec(RustSimStruct(OrderedDict(x=RustSimTypeInt(32))))
        right = RustSimTypeVec(RustSimStruct(OrderedDict(y=RustSimTypeInt(64))))
        parent = RustSimStruct(OrderedDict(left=left, right=right), name="Holder").with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        arched_left, arched_right = parent.fields["left"], parent.fields["right"]
        assert isinstance(arched_left, RustSimTypeVec)
        assert isinstance(arched_right, RustSimTypeVec)
        assert arched_left.name == arched_right.name == "Vec<<anon>>"
        assert arched_left is not arched_right
        assert isinstance(arched_left.element_type, RustSimStruct)
        assert isinstance(arched_right.element_type, RustSimStruct)
        assert list(arched_left.element_type.fields) == ["x"]
        assert list(arched_right.element_type.fields) == ["y"]

    def test_vecs_with_the_same_named_element_preserve_their_layouts(self):
        for roundtrip in (False, True):
            with self.subTest(roundtrip=roundtrip):
                element = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)), name="El")
                left = RustSimTypeVec(element, label="left")
                right = RustSimTypeVec(element, order=("ptr", "cap", "len"), label="right")
                prototype = SimTypeFunction([left, right], None)
                if roundtrip:
                    prototype = SimType.from_json(json.loads(json.dumps(prototype.to_json())))
                arched = prototype.with_arch(archinfo.ArchAMD64())
                assert isinstance(arched, SimTypeFunction)
                arched_left, arched_right = arched.args
                assert isinstance(arched_left, RustSimTypeVec)
                assert isinstance(arched_right, RustSimTypeVec)
                self.assertIsNot(arched_left, arched_right)
                self.assertIs(arched_left.element_type, arched_right.element_type)
                self.assertEqual(arched_left.offsets, {"cap": 0, "ptr": 8, "len": 16})
                self.assertEqual(arched_right.offsets, {"ptr": 0, "cap": 8, "len": 16})
                self.assertEqual(arched_right.order, ("ptr", "cap", "len"))
                self.assertEqual((arched_left.label, arched_right.label), ("left", "right"))

    def test_rust_wrapper_cycles_preserve_payload_identity(self):
        for kind in ("vec", "option", "result"):
            with self.subTest(kind=kind):
                payload = RustSimStruct(OrderedDict(), name="Payload")
                if kind == "vec":
                    wrapper = RustSimTypeVec(payload)
                elif kind == "option":
                    wrapper = RustSimTypeOption(0, 1, payload, 1, 1)
                else:
                    wrapper = RustSimTypeResult(payload, 0, 1, RustSimTypeInt(32), 1, 1)
                payload.fields["back"] = SimTypePointer(wrapper)
                arched = wrapper.with_arch(archinfo.ArchAMD64())
                if isinstance(arched, RustSimTypeVec):
                    arched_payload = arched.element_type
                    pointer = arched.fields["ptr"]
                    assert isinstance(pointer, RustSimTypeReference)
                    self.assertIs(arched_payload, pointer.pts_to)
                elif isinstance(arched, RustSimTypeOption):
                    arched_payload = arched.some_type
                    self.assertIs(arched_payload, arched.variants[1].fields[0][0])
                else:
                    assert isinstance(arched, RustSimTypeResult)
                    arched_payload = arched.ok_type
                    self.assertIs(arched_payload, arched.variants[0].fields[0][0])
                    self.assertIs(arched.err_type, arched.variants[1].fields[0][0])
                assert isinstance(arched_payload, RustSimStruct)
                back = arched_payload.fields["back"]
                assert isinstance(back, SimTypePointer)
                self.assertIs(back.pts_to, arched)

    def test_shared_rust_result_payloads_are_converted_once(self):
        node: SimType = RustSimStruct(OrderedDict(value=RustSimTypeInt(32)), name="Leaf")
        depth = 18
        for index in range(depth):
            node = RustSimTypeResult(node, 0, 1, node, 1, 1, name=f"Layer{index}")
        arched = node.with_arch(archinfo.ArchAMD64())
        for _ in range(depth):
            assert isinstance(arched, RustSimTypeResult)
            self.assertIs(arched.ok_type, arched.err_type)
            self.assertIs(arched.ok_type, arched.variants[0].fields[0][0])
            self.assertIs(arched.err_type, arched.variants[1].fields[0][0])
            arched = arched.ok_type
        assert isinstance(arched, RustSimStruct)
        self.assertEqual(list(arched.fields), ["value"])

    def test_generated_rust_enum_names_do_not_identify_payloads(self):
        for name in ("enum_8", "enum_32", "enum8", "enum32"):
            with self.subTest(name=name):
                left = RustSimEnum(name, [EnumVariant("variant8", [(RustSimTypeInt(32), "x")], 0, 1)])
                right = RustSimEnum(name, [EnumVariant("variant8", [(RustSimTypeInt(64), "y")], 0, 1)])
                prototype = SimTypeFunction([left, right], None)
                arched = prototype.with_arch(archinfo.ArchAMD64())
                assert isinstance(arched, SimTypeFunction)
                arched_left, arched_right = arched.args
                assert isinstance(arched_left, RustSimEnum)
                assert isinstance(arched_right, RustSimEnum)
                self.assertIsNot(arched_left, arched_right)
                self.assertEqual(arched_left.variants[0].fields[0][1], "x")
                self.assertEqual(arched_right.variants[0].fields[0][1], "y")
                restored = SimType.from_json(json.loads(json.dumps(prototype.to_json())))
                assert isinstance(restored, SimTypeFunction)
                self.assertIsInstance(restored.args[0], RustSimEnum)
                self.assertIsInstance(restored.args[1], SimTypeRef)

    def test_generated_enum_names_do_not_change_named_struct_identity(self):
        for name in ("enum8", "enum_8", "variant8"):
            with self.subTest(name=name):
                defined = RustSimStruct(OrderedDict(value=RustSimTypeInt(32)), name=name)
                forward = RustSimStruct(OrderedDict(), name=name)
                arched = SimTypeFunction([defined, forward], None).with_arch(archinfo.ArchAMD64())
                assert isinstance(arched, SimTypeFunction)
                self.assertIs(arched.args[0], arched.args[1])
                restored = SimType.from_json(
                    json.loads(json.dumps(SimTypeFunction([defined, forward], None).to_json()))
                )
                assert isinstance(restored, SimTypeFunction)
                self.assertIs(restored.args[0], restored.args[1])

    def test_two_options_of_nameless_rust_structs_stay_distinct(self):
        left = RustSimTypeOption(0, 1, RustSimStruct(OrderedDict(x=RustSimTypeInt(32))), 1, 1)
        right = RustSimTypeOption(0, 1, RustSimStruct(OrderedDict(y=RustSimTypeInt(64))), 1, 1)
        parent = RustSimStruct(OrderedDict(left=left, right=right), name="Holder").with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        arched_left, arched_right = parent.fields["left"], parent.fields["right"]
        assert isinstance(arched_left, RustSimTypeOption)
        assert isinstance(arched_right, RustSimTypeOption)
        assert arched_left is not arched_right
        assert isinstance(arched_left.some_type, RustSimStruct)
        assert isinstance(arched_right.some_type, RustSimStruct)
        assert list(arched_left.some_type.fields) == ["x"]
        assert list(arched_right.some_type.fields) == ["y"]

    def test_nested_wrappers_of_nameless_rust_structs_stay_distinct(self):
        # Option<Vec<<anon>>>: the placeholder reaches the outer name through the inner one
        left = RustSimTypeOption(0, 1, RustSimTypeVec(RustSimStruct(OrderedDict(x=RustSimTypeInt(32)))), 1, 1)
        right = RustSimTypeOption(0, 1, RustSimTypeVec(RustSimStruct(OrderedDict(y=RustSimTypeInt(64)))), 1, 1)
        parent = RustSimStruct(OrderedDict(left=left, right=right), name="Holder").with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        payloads = []
        for side in ("left", "right"):
            option = parent.fields[side]
            assert isinstance(option, RustSimTypeOption)
            assert option.name == "Option<Vec<<anon>>>"
            vec = option.some_type
            assert isinstance(vec, RustSimTypeVec)
            assert isinstance(vec.element_type, RustSimStruct)
            payloads.append(list(vec.element_type.fields))
        assert payloads == [["x"], ["y"]]

    def test_two_flagged_anonymous_rust_structs_stay_distinct(self):
        # SimStruct marks `_Anonymous_e__Struct` anonymous under a name of its own, so the name
        # identifies nothing even though it is not the placeholder. The flag is the contract.
        left = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)), name="_Anonymous_e__Struct")
        right = RustSimStruct(OrderedDict(y=RustSimTypeInt(64)), name="_Anonymous_e__Struct")
        assert left.anonymous and right.anonymous
        parent = RustSimStruct(OrderedDict(left=left, right=right), name="Holder").with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        arched_left, arched_right = parent.fields["left"], parent.fields["right"]
        assert isinstance(arched_left, RustSimStruct)
        assert isinstance(arched_right, RustSimStruct)
        assert list(arched_left.fields) == ["x"]
        assert list(arched_right.fields) == ["y"]
        assert arched_left.anonymous is True

    def test_two_vecs_of_flagged_anonymous_structs_stay_distinct(self):
        # the wrapper's own name carries no placeholder here: Vec<_Anonymous_e__Struct>
        left = RustSimTypeVec(RustSimStruct(OrderedDict(x=RustSimTypeInt(32)), name="_Anonymous_e__Struct"))
        right = RustSimTypeVec(RustSimStruct(OrderedDict(y=RustSimTypeInt(64)), name="_Anonymous_e__Struct"))
        assert ANON_STRUCT_NAME not in left.name
        parent = RustSimStruct(OrderedDict(left=left, right=right), name="Holder").with_arch(archinfo.ArchAMD64())
        assert isinstance(parent, RustSimStruct)
        payloads = []
        for side in ("left", "right"):
            vec = parent.fields[side]
            assert isinstance(vec, RustSimTypeVec)
            assert isinstance(vec.element_type, RustSimStruct)
            payloads.append(list(vec.element_type.fields))
        assert payloads == [["x"], ["y"]]

    def test_a_struct_whose_own_name_looks_like_a_placeholder_still_resolves(self):
        # only a struct that was given no name is refused as a reference target; a name of its own
        # is registered whatever it looks like
        ty = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)), name="Wrapper<<anon>>")
        document = SimTypeFunction([ty, ty], RustSimTypeInt(32)).to_json()
        assert document["args"][1] == {"_t": "_ref", "name": "Wrapper<<anon>>", "ot": "rust_struct"}
        restored = SimType.from_json(json.loads(json.dumps(document)))
        assert isinstance(restored, SimTypeFunction)
        assert isinstance(restored.args[1], RustSimStruct)
        assert restored.args[0] is restored.args[1]

    def test_a_cycle_back_to_a_named_root_terminates_through_each_wrapper(self):
        # These recursed for ever before the memo was carried into a Rust type's members, and they
        # have to keep terminating: the identity key is only for a name that identifies nothing.
        for wrap in (
            lambda t: t,
            RustSimTypeVec,
            lambda t: RustSimTypeOption(0, 1, t, 1, 1),
            lambda t: RustSimTypeResult(t, 0, 1, RustSimTypeInt(32), 1, 1),
        ):
            root = SimStruct(OrderedDict(), name="Outer")
            inner = RustSimStruct(OrderedDict())
            inner.fields["back"] = SimTypePointer(root)
            root.fields["inner"] = wrap(inner)
            arched = root.with_arch(archinfo.ArchAMD64())
            assert isinstance(arched, SimStruct)
            arched_inner = arched.fields["inner"]
            for attr in ("element_type", "some_type", "ok_type"):
                arched_inner = getattr(arched_inner, attr, arched_inner)
            # the converted child points back at the converted root, not at the one it came from
            assert isinstance(arched_inner, RustSimStruct)
            back = arched_inner.fields["back"]
            assert isinstance(back, SimTypePointer)
            assert back.pts_to is arched
            assert arched_inner is not inner

    def test_a_nameless_rust_struct_is_not_a_reference_target_on_decode(self):
        # to_json emits the second anonymous struct as a reference to "<anon>", a name every
        # anonymous struct shares. Resolving it would hand back an unrelated type, so it is left
        # unresolved exactly as before; the field the encoder dropped is a separate defect.
        left = RustSimStruct(OrderedDict(x=RustSimTypeInt(32)))
        right = RustSimStruct(OrderedDict(y=RustSimTypeInt(64)))
        document = SimTypeFunction([left, right], RustSimTypeInt(32)).to_json()
        assert document["args"][1] == {"_t": "_ref", "name": "<anon>", "ot": "rust_struct"}
        restored = SimType.from_json(json.loads(json.dumps(document)))
        assert isinstance(restored.args[0], RustSimStruct)
        assert list(restored.args[0].fields) == ["x"]
        assert isinstance(restored.args[1], SimTypeRef)

    def test_a_cycle_that_runs_through_a_rust_struct_can_be_arched(self):
        # A named SimStruct is registered as a reference target before its fields are decoded, so a
        # reference back to it from inside a RustSimStruct below it resolves and the object graph is
        # genuinely cyclic -- as it already was for a cycle between two plain SimStructs.
        # RustSimStruct._with_arch has to carry the memo through its fields for that to terminate.
        outer = SimStruct(OrderedDict(), name="Outer")
        inner = RustSimStruct(OrderedDict(), name="Inner")
        inner.fields["back"] = SimTypePointer(TypeRef("Outer", outer))
        outer.fields["inner"] = inner

        restored = SimType.from_json(json.loads(json.dumps(outer.to_json())))
        assert isinstance(restored, SimStruct) and restored.name == "Outer"
        restored_inner = restored.fields["inner"]
        assert isinstance(restored_inner, RustSimStruct)
        pointer = restored_inner.fields["back"]
        assert isinstance(pointer, SimTypePointer)
        back = pointer.pts_to
        assert back is restored or getattr(back, "type", None) is restored

        # with_arch has to terminate over that cycle
        arched = restored.with_arch(archinfo.ArchAMD64())
        assert isinstance(arched, SimStruct)
        arched_inner = arched.fields["inner"]
        assert isinstance(arched_inner, RustSimStruct)
        assert isinstance(arched_inner.fields["back"], SimTypePointer)

    def test_a_cycle_that_runs_through_a_rust_vec_can_be_arched(self):
        # The same cycle through RustSimTypeVec, whose _with_arch hands the element to its own
        # constructor: the constructor wraps it in a fresh RustSimTypeReference and walks that with
        # a memo of its own when given an arch, so arch its fields separately with the outer memo.
        outer = SimStruct(OrderedDict(), name="Outer")
        outer.fields["v"] = RustSimTypeVec(SimTypePointer(TypeRef("Outer", outer)))

        restored = SimType.from_json(json.loads(json.dumps(outer.to_json())))
        assert isinstance(restored, SimStruct)
        arched = restored.with_arch(archinfo.ArchAMD64())
        assert isinstance(arched, SimStruct)
        assert isinstance(arched.fields["v"], RustSimTypeVec)

    def test_a_rust_enum_used_twice_survives_a_function_prototype_round_trip(self):
        # The same thing on the path FunctionParser uses, which is what an AngrDB save and load
        # does to every prototype, and what the function manager's own spill does during analysis.
        project = angr.Project(os.path.join(bin_location, "tests", "x86_64", "rust_hello_world"), auto_load_libs=False)
        count = RustSimEnum(
            "core::fmt::rt::Count",
            [
                EnumVariant.from_no_data("Implied", 0, 8),
                EnumVariant.from_single_field_ty("Is", RustSimTypeSize(signed=False), 1, 8),
            ],
        )
        prototype = SimTypeFunction([count, count], RustSimTypeInt(32)).with_arch(project.arch)
        assert isinstance(prototype, SimTypeFunction)
        function = project.kb.functions.function(addr=project.entry, create=True)
        assert function is not None
        function.prototype = prototype

        back = FunctionParser.parse_from_cmsg(
            FunctionParser.serialize(function), function_manager=project.kb.functions, project=project
        )
        assert back.prototype is not None
        for argument in back.prototype.args:
            assert isinstance(argument, RustSimEnum)
            assert [variant.name for variant in argument.variants] == ["Implied", "Is"]

    def test_rust_slice_layout_uses_two_machine_words(self):
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

    def test_rust_type_translator_handles_rust_simtypes_and_type_constants(self):
        arch = archinfo.ArchAMD64()
        translator = RustTypeTranslator(arch)

        struct_tc = typeconsts.Struct(
            fields={0: typeconsts.Int16(), 4: typeconsts.Pointer64(typeconsts.Int8())},
            field_names={0: "tag", 4: "ptr"},
            name="Pair",
        )
        struct_ty, has_nonexistent_ref = translator.tc2simtype(struct_tc)
        assert has_nonexistent_ref is False
        assert isinstance(struct_ty, RustSimStruct)
        assert struct_ty.name == "Pair"
        assert list(struct_ty.fields) == ["tag", "ptr"]
        assert isinstance(struct_ty.fields["tag"], RustSimTypeInt)
        assert struct_ty.fields["tag"].size == 16
        assert isinstance(struct_ty.fields["ptr"], RustSimTypeReference)

        array_ty, has_nonexistent_ref = translator.tc2simtype(typeconsts.Array(typeconsts.Int32(), 2))
        assert has_nonexistent_ref is False
        assert isinstance(array_ty, RustSimTypeArray)
        assert array_ty.length == 2
        assert isinstance(array_ty.elem_type, RustSimTypeInt)
        assert array_ty.elem_type.size == 32

        result_tc = typeconsts.RustEnum(
            "core::result::Result<u64, u16>",
            [
                typeconsts.EnumVariant("Ok", [(typeconsts.Int64(), "__0")], 0, 1, 8),
                typeconsts.EnumVariant("Err", [(typeconsts.Int16(), "__0")], 1, 1, 2),
            ],
        )
        result_ty, has_nonexistent_ref = translator.tc2simtype(result_tc)
        assert has_nonexistent_ref is False
        assert isinstance(result_ty, RustSimTypeResult)
        assert result_ty.get_variant(0) is not None

        option_tc = typeconsts.RustEnum(
            "core::option::Option<u32>",
            [
                typeconsts.EnumVariant("None", [], 0, 1, 0),
                typeconsts.EnumVariant("Some", [(typeconsts.Int32(), "__0")], 1, 1, 4),
            ],
        )
        option_ty, has_nonexistent_ref = translator.tc2simtype(option_tc)
        assert has_nonexistent_ref is False
        assert isinstance(option_ty, RustSimTypeOption)
        assert option_ty.get_variant_by_name("Some") is not None

        lifted_struct = translator.simtype2tc(
            RustSimStruct(OrderedDict({"value": RustSimTypeInt(32, signed=False)}), name="Lifted", pack=True).with_arch(
                arch
            )
        )
        assert isinstance(lifted_struct, typeconsts.Struct)
        assert lifted_struct.field_names == {0: "value"}

        lifted_enum = translator.simtype2tc(
            RustSimEnum(
                "EnumLike",
                [
                    EnumVariant.from_no_data("None", 0, 1),
                    EnumVariant.from_single_field_ty("Some", RustSimTypeInt(8), 1, 1),
                ],
            ).with_arch(arch)
        )
        assert isinstance(lifted_enum, typeconsts.RustEnum)
        assert lifted_enum.get_variant("Some") is not None

    def test_type_db_loader_parses_structs_slices_and_enums(self):
        loader = _blank_type_db_loader()

        bool_ty = loader._parse_type({"kind": "Primitive", "name": "bool", "size": 1})
        assert bool_ty is not None
        assert bool_ty.size == 8
        assert loader._parse_type({"kind": "Primitive", "name": "f32", "size": 4}) is None

        str_data = {
            "kind": "Struct",
            "name": "&str",
            "fields": {
                "0": ["data_ptr", {"kind": "Pointer", "pts_to": {"kind": "Primitive", "name": "u8", "size": 1}}],
                "8": ["length", {"kind": "Primitive", "name": "usize", "size": 8}],
            },
        }
        str_ty = loader._parse_type(str_data)
        assert isinstance(str_ty, RustSimTypeStrRef)

        vec_data = {
            "kind": "Struct",
            "name": "Vec2",
            "fields": {
                "0": [
                    "items",
                    {"kind": "Array", "ele_type": {"kind": "Primitive", "name": "u16", "size": 2}, "length": 2},
                ]
            },
        }
        vec_ty = loader._parse_type(vec_data)
        assert isinstance(vec_ty, RustSimStruct)
        assert isinstance(vec_ty.fields["items"], RustSimTypeArray)

        option_ty = loader._parse_type(
            {
                "kind": "Enumeration",
                "name": "core::option::Option<u32>",
                "discriminant_size": 1,
                "variants": {
                    "None": [0, []],
                    "Some": [1, [["__0", {"kind": "Primitive", "name": "u32", "size": 4}]]],
                },
            }
        )
        assert isinstance(option_ty, RustSimTypeOption)

        result_ty = loader._parse_type(
            {
                "kind": "Enumeration",
                "name": "core::result::Result<u64, u16>",
                "discriminant_size": 1,
                "variants": {
                    "Ok": [0, [["__0", {"kind": "Primitive", "name": "u64", "size": 8}]]],
                    "Err": [1, [["__0", {"kind": "Primitive", "name": "u16", "size": 2}]]],
                },
            }
        )
        assert isinstance(result_ty, RustSimTypeResult)

    def test_type_db_loader_fits_and_negotiates_large_abi_types(self):
        loader = _blank_type_db_loader()
        large_struct = RustSimStruct(
            OrderedDict(
                {
                    "a": RustSimTypeInt(64, signed=False),
                    "b": RustSimTypeInt(64, signed=False),
                    "c": RustSimTypeInt(64, signed=False),
                }
            ),
            name="Large",
            pack=True,
        ).with_arch(loader.project.arch)

        direct_arg = loader._fit_abi(RustSimTypeFunction([large_struct], RustSimTypeInt(32, signed=False))).with_arch(
            loader.project.arch
        )
        assert isinstance(direct_arg.args[0], RustSimTypeReference)
        assert direct_arg.returnty is not None

        retbuf = loader._fit_abi(RustSimTypeFunction([], large_struct)).with_arch(loader.project.arch)
        assert retbuf.returnty is None
        assert retbuf.is_arg0_retbuf is True
        assert isinstance(retbuf.args[0], RustSimTypeReference)

        two_word_struct = RustSimStruct(
            OrderedDict({"a": RustSimTypeInt(64, signed=False), "b": RustSimTypeInt(64, signed=False)}),
            name="Pair",
            pack=True,
        ).with_arch(loader.project.arch)
        rust_proto = RustSimTypeFunction([], two_word_struct).with_arch(loader.project.arch)
        old_direct = SimTypeFunction([], SimTypeArray(SimTypeLongLong(signed=False), 2)).with_arch(loader.project.arch)
        assert loader._negotiate_prototype(rust_proto, old_direct) is rust_proto


if __name__ == "__main__":
    unittest.main()
