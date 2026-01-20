#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Tests for SimTypeEnum and SimTypeBitfield types."""

from __future__ import annotations

import unittest

import archinfo

from angr.sim_type import (
    SimTypeEnum,
    SimTypeBitfield,
    SimTypeInt,
    SimTypeLong,
    SimTypeFunction,
    SimTypePointer,
    SimTypeChar,
    TypeRef,
    parse_type,
)


class TestSimTypeEnum(unittest.TestCase):
    """Test cases for SimTypeEnum."""

    def test_basic_enum_creation(self):
        """Test basic enum type creation."""
        enum = SimTypeEnum(
            members={"FOO": 0, "BAR": 1, "BAZ": 2},
            name="my_enum",
        )
        assert enum._name == "my_enum"
        assert enum.members == {"FOO": 0, "BAR": 1, "BAZ": 2}
        assert repr(enum) == "enum my_enum"

    def test_enum_anonymous(self):
        """Test anonymous enum (no name)."""
        enum = SimTypeEnum(members={"A": 0, "B": 1})
        assert enum._name == "<anon>"
        assert repr(enum) == "enum <anon>"

    def test_enum_resolve(self):
        """Test resolving integer values to enum member names."""
        enum = SimTypeEnum(
            members={"STDIN": 0, "STDOUT": 1, "STDERR": 2},
            name="stdio_fd",
        )
        assert enum.resolve(0) == "STDIN"
        assert enum.resolve(1) == "STDOUT"
        assert enum.resolve(2) == "STDERR"
        assert enum.resolve(99) is None  # Unknown value

    def test_enum_custom_base_type(self):
        """Test enum with custom base type."""
        enum = SimTypeEnum(
            members={"A": 0, "B": 1},
            base_type=SimTypeLong(signed=False),
            name="long_enum",
        )
        assert isinstance(enum.base_type, SimTypeLong)

    def test_enum_default_base_type(self):
        """Test enum default base type is unsigned int."""
        enum = SimTypeEnum(members={"A": 0}, name="test")
        assert isinstance(enum.base_type, SimTypeInt)
        assert not enum.base_type.signed

    def test_enum_size_and_alignment(self):
        """Test enum size and alignment derived from base type."""
        arch = archinfo.ArchAMD64()
        enum = SimTypeEnum(members={"A": 0}, name="test")
        enum = enum.with_arch(arch)
        # Default is unsigned int, which is 32 bits on AMD64
        assert enum.size == 32
        assert enum.alignment == 4

    def test_enum_with_arch(self):
        """Test enum with_arch method."""
        enum = SimTypeEnum(
            members={"A": 0, "B": 1},
            name="test",
            qualifier=["const"],
        )
        arch = archinfo.ArchAMD64()
        enum_with_arch = enum.with_arch(arch)
        assert enum_with_arch._arch == arch
        assert enum_with_arch.members == enum.members
        assert enum_with_arch._name == enum._name
        assert enum_with_arch.label == enum.label
        assert enum_with_arch.qualifier == ["const"]

    def test_enum_c_repr_short(self):
        """Test enum C representation (short form)."""
        enum = SimTypeEnum(
            members={"A": 0, "B": 1},
            name="my_enum",
        )
        assert enum.c_repr() == "enum my_enum"
        assert enum.c_repr(name="var") == "enum my_enum var"

    def test_enum_c_repr_with_qualifier(self):
        """Test enum C representation with qualifier."""
        enum = SimTypeEnum(
            members={"A": 0},
            name="my_enum",
            qualifier=["const"],
        )
        assert enum.c_repr() == "const enum my_enum"

    def test_enum_c_repr_full(self):
        """Test enum C representation (full form with members)."""
        enum = SimTypeEnum(
            members={"FOO": 0, "BAR": 1},
            name="my_enum",
        )
        full_repr = enum.c_repr(full=1)
        assert "enum my_enum" in full_repr
        assert "FOO = 0" in full_repr
        assert "BAR = 1" in full_repr

    def test_enum_hash(self):
        """Test enum hashing for use in sets/dicts."""
        enum1 = SimTypeEnum(members={"A": 0, "B": 1}, name="test")
        enum2 = SimTypeEnum(members={"A": 0, "B": 1}, name="test")
        enum3 = SimTypeEnum(members={"A": 0, "C": 2}, name="test")

        assert hash(enum1) == hash(enum2)
        assert hash(enum1) != hash(enum3)

        # Test use in set
        s = {enum1}
        assert enum2 in s  # Same hash

    def test_enum_copy(self):
        """Test enum copy method."""
        enum = SimTypeEnum(
            members={"A": 0, "B": 1},
            name="test",
            qualifier=["const"],
        )
        copied = enum.copy()
        assert copied.members == enum.members
        assert copied._name == enum._name
        assert copied.label == enum.label
        assert copied.qualifier == enum.qualifier
        # Ensure it's a deep copy of members
        copied.members["C"] = 2
        assert "C" not in enum.members

    def test_enum_init_str(self):
        """Test enum _init_str for serialization."""
        enum = SimTypeEnum(
            members={"A": 0, "B": 1},
            name="test",
        )
        init_str = enum._init_str()
        assert "SimTypeEnum" in init_str
        assert '"A": 0' in init_str
        assert '"B": 1' in init_str
        assert 'name="test"' in init_str


class TestSimTypeBitfield(unittest.TestCase):
    """Test cases for SimTypeBitfield."""

    def test_basic_bitfield_creation(self):
        """Test basic bitfield type creation."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2, "EXEC": 4},
            name="prot_flags",
        )
        assert bf._name == "prot_flags"
        assert bf.flags == {"READ": 1, "WRITE": 2, "EXEC": 4}
        assert repr(bf) == "bitfield prot_flags"

    def test_bitfield_anonymous(self):
        """Test anonymous bitfield."""
        bf = SimTypeBitfield(flags={"A": 1, "B": 2})
        assert bf._name == "<anon>"

    def test_bitfield_resolve_single_flag(self):
        """Test resolving single flag values."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2, "EXEC": 4},
            name="prot",
        )
        flags, unknown = bf.resolve(1)
        assert flags == ["READ"]
        assert unknown == 0

        flags, unknown = bf.resolve(2)
        assert flags == ["WRITE"]
        assert unknown == 0

    def test_bitfield_resolve_combined_flags(self):
        """Test resolving combined flag values."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2, "EXEC": 4},
            name="prot",
        )
        flags, unknown = bf.resolve(3)  # READ | WRITE
        assert set(flags) == {"READ", "WRITE"}
        assert unknown == 0

        flags, unknown = bf.resolve(7)  # READ | WRITE | EXEC
        assert set(flags) == {"READ", "WRITE", "EXEC"}
        assert unknown == 0

    def test_bitfield_resolve_unknown_bits(self):
        """Test resolving values with unknown bits."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2},
            name="prot",
        )
        flags, unknown = bf.resolve(5)  # READ | 4 (unknown)
        assert "READ" in flags
        assert unknown == 4

    def test_bitfield_resolve_zero(self):
        """Test resolving zero value."""
        bf = SimTypeBitfield(
            flags={"NONE": 0, "READ": 1},
            name="prot",
        )
        flags, unknown = bf.resolve(0)
        assert flags == ["NONE"]
        assert unknown == 0

    def test_bitfield_render(self):
        """Test rendering bitfield values to strings."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2, "EXEC": 4},
            name="prot",
        )
        assert bf.render(1) == "READ"
        # Combined flags - order may vary, so check both parts
        rendered = bf.render(3)
        assert "READ" in rendered and "WRITE" in rendered and "|" in rendered

        # Zero with no NONE flag
        bf2 = SimTypeBitfield(flags={"READ": 1}, name="prot")
        assert bf2.render(0) == "0"

    def test_bitfield_render_unknown_bits(self):
        """Test rendering values with unknown bits."""
        bf = SimTypeBitfield(
            flags={"READ": 1},
            name="prot",
        )
        rendered = bf.render(5)  # READ | 4 (unknown)
        assert "READ" in rendered
        assert "0x4" in rendered

    def test_bitfield_has_unknown_bits(self):
        """Test has_unknown_bits method."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2},
            name="prot",
        )
        assert not bf.has_unknown_bits(1)
        assert not bf.has_unknown_bits(3)
        assert bf.has_unknown_bits(4)
        assert bf.has_unknown_bits(5)

    def test_bitfield_validate(self):
        """Test validate method."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2},
            name="prot",
        )
        assert bf.validate(1)
        assert bf.validate(3)
        assert not bf.validate(4)
        assert not bf.validate(5)

    def test_bitfield_size_and_alignment(self):
        """Test bitfield size and alignment from base type."""
        arch = archinfo.ArchAMD64()
        bf = SimTypeBitfield(flags={"A": 1}, name="test")
        bf = bf.with_arch(arch)
        assert bf.size == 32
        assert bf.alignment == 4

    def test_bitfield_with_arch(self):
        """Test bitfield with_arch method."""
        bf = SimTypeBitfield(
            flags={"A": 1, "B": 2},
            name="test",
            qualifier=["const"],
        )
        arch = archinfo.ArchAMD64()
        bf_with_arch = bf.with_arch(arch)
        assert bf_with_arch._arch == arch
        assert bf_with_arch.flags == bf.flags
        assert bf_with_arch._name == bf._name

    def test_bitfield_c_repr(self):
        """Test bitfield C representation."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2},
            name="prot_flags",
        )
        # Short form uses enum syntax
        assert bf.c_repr() == "enum prot_flags"

    def test_bitfield_c_repr_full(self):
        """Test bitfield full C representation."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2},
            name="prot_flags",
        )
        full_repr = bf.c_repr(full=1)
        assert "enum prot_flags" in full_repr
        assert "READ = 0x1" in full_repr
        assert "WRITE = 0x2" in full_repr

    def test_bitfield_hash(self):
        """Test bitfield hashing."""
        bf1 = SimTypeBitfield(flags={"A": 1, "B": 2}, name="test")
        bf2 = SimTypeBitfield(flags={"A": 1, "B": 2}, name="test")
        bf3 = SimTypeBitfield(flags={"A": 1, "C": 4}, name="test")

        assert hash(bf1) == hash(bf2)
        assert hash(bf1) != hash(bf3)

    def test_bitfield_copy(self):
        """Test bitfield copy method."""
        bf = SimTypeBitfield(
            flags={"A": 1, "B": 2},
            name="test",
        )
        copied = bf.copy()
        assert copied.flags == bf.flags
        assert copied._name == bf._name
        # Ensure deep copy
        copied.flags["C"] = 4
        assert "C" not in bf.flags

    def test_bitfield_init_str(self):
        """Test bitfield _init_str."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2},
            name="test",
        )
        init_str = bf._init_str()
        assert "SimTypeBitfield" in init_str
        assert '"READ": 0x1' in init_str
        assert 'name="test"' in init_str


class TestEnumInTypeRef(unittest.TestCase):
    """Test enum types used with TypeRef."""

    def test_enum_in_typeref(self):
        """Test storing enum in TypeRef."""
        enum = SimTypeEnum(
            members={"A": 0, "B": 1},
            name="my_enum",
        )
        ref = TypeRef("my_enum", enum)
        assert ref.name == "my_enum"
        assert ref.type == enum
        assert isinstance(ref.type, SimTypeEnum)

    def test_bitfield_in_typeref(self):
        """Test storing bitfield in TypeRef."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2},
            name="prot_flags",
        )
        ref = TypeRef("prot_flags", bf)
        assert ref.name == "prot_flags"
        assert ref.type == bf
        assert isinstance(ref.type, SimTypeBitfield)


class TestEnumInFunctionPrototype(unittest.TestCase):
    """Test enum types in function prototypes."""

    def test_enum_as_parameter(self):
        """Test using enum as function parameter type."""
        enum = SimTypeEnum(
            members={"STDIN": 0, "STDOUT": 1, "STDERR": 2},
            name="stdio_fd",
        )
        proto = SimTypeFunction(
            args=[enum, SimTypePointer(SimTypeChar()), SimTypeInt()],
            returnty=SimTypeInt(),
        )
        assert proto.args[0] == enum
        assert isinstance(proto.args[0], SimTypeEnum)

    def test_enum_as_return_type(self):
        """Test using enum as function return type."""
        enum = SimTypeEnum(
            members={"SUCCESS": 0, "FAILURE": 1},
            name="result_t",
        )
        proto = SimTypeFunction(
            args=[],
            returnty=enum,
        )
        assert proto.returnty == enum
        assert isinstance(proto.returnty, SimTypeEnum)

    def test_bitfield_as_parameter(self):
        """Test using bitfield as function parameter type."""
        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2, "EXEC": 4},
            name="prot_flags",
        )
        proto = SimTypeFunction(
            args=[SimTypePointer(SimTypeChar()), SimTypeInt(), bf],
            returnty=SimTypeInt(),
        )
        assert proto.args[2] == bf
        assert isinstance(proto.args[2], SimTypeBitfield)


class TestEnumEdgeCases(unittest.TestCase):
    """Test edge cases for enum handling."""

    def test_empty_enum(self):
        """Test handling of empty enum."""
        empty = SimTypeEnum({}, name="Empty")
        assert empty.members == {}  # pylint:disable=use-implicit-booleaness-not-comparison
        assert empty.c_repr(full=1) == "enum Empty {\n\n}"

    def test_single_member_enum(self):
        """Test enum with single member."""
        single = SimTypeEnum({"ONLY": 42}, name="Single")
        assert single.members == {"ONLY": 42}
        c_repr = single.c_repr(full=1)
        assert "ONLY = 42" in c_repr

    def test_large_enum_values(self):
        """Test enum with large values."""
        large = SimTypeEnum({"MIN": -2147483648, "MAX": 2147483647, "ZERO": 0}, name="Limits")

        assert large.members["MIN"] == -2147483648
        assert large.members["MAX"] == 2147483647

    def test_enum_with_special_names(self):
        """Test enum with various naming conventions."""
        special = SimTypeEnum(
            {
                "ALL_CAPS": 0,
                "mixedCase": 1,
                "with_underscore": 2,
                "_leading": 3,
                "trailing_": 4,
            },
            name="SpecialNames",
        )

        # All names should be preserved
        assert len(special.members) == 5
        for name in ["ALL_CAPS", "mixedCase", "with_underscore", "_leading", "trailing_"]:
            assert name in special.members

    def test_parse_enum_with_hex_values(self):
        """Test parsing enum with hexadecimal values."""
        enum_type = parse_type("enum Flags { NONE = 0x0, READ = 0x1, WRITE = 0x2, EXEC = 0x4 }")
        assert isinstance(enum_type, SimTypeEnum)
        assert enum_type.members["NONE"] == 0
        assert enum_type.members["READ"] == 1
        assert enum_type.members["WRITE"] == 2
        assert enum_type.members["EXEC"] == 4

    def test_parse_enum_with_expressions(self):
        """Test parsing enum with constant expressions."""
        enum_type = parse_type("enum Bits { B0 = 1, B1 = 1 << 1, B2 = 1 << 2, B3 = 1 << 3 }")
        assert isinstance(enum_type, SimTypeEnum)
        assert enum_type.members["B0"] == 1
        assert enum_type.members["B1"] == 2
        assert enum_type.members["B2"] == 4
        assert enum_type.members["B3"] == 8


if __name__ == "__main__":
    unittest.main()
