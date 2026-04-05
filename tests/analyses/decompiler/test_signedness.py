#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""Tests for signed/unsigned integer type inference in the decompiler."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo
import networkx

from angr.analyses.typehoon.typeconsts import (
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
    SInt8,
    UInt8,
    SInt16,
    UInt16,
    SInt32,
    UInt32,
    SInt64,
    UInt64,
    int_type,
    signed_int_type,
    unsigned_int_type,
)
from angr.analyses.typehoon.simple_solver import (
    BASE_LATTICE_32,
    BASE_LATTICE_64,
    Bottom_,
    Int8_,
    Int16_,
    Int32_,
    Int64_,
    SInt8_,
    UInt8_,
    SInt16_,
    UInt16_,
    SInt32_,
    UInt32_,
    SInt64_,
    UInt64_,
    PRIMITIVE_TYPES,
)
from angr.analyses.typehoon.translator import TypeTranslator
from angr.sim_type import SimTypeInt, SimTypeShort, SimTypeChar, SimTypeLongLong


class TestTypeConsts(unittest.TestCase):
    """Test the signed/unsigned type constant classes."""

    def test_class_hierarchy(self):
        """SIntN should be a subclass of IntN, and IntN of Int."""
        assert isinstance(SInt8(), Int8)
        assert isinstance(SInt8(), Int)
        assert isinstance(UInt8(), Int8)
        assert isinstance(UInt8(), Int)
        assert isinstance(SInt16(), Int16)
        assert isinstance(UInt16(), Int16)
        assert isinstance(SInt32(), Int32)
        assert isinstance(UInt32(), Int32)
        assert isinstance(SInt64(), Int64)
        assert isinstance(UInt64(), Int64)

    def test_equality_distinct(self):
        """SIntN != IntN != UIntN (distinct types in the lattice)."""
        assert SInt32() != Int32()
        assert UInt32() != Int32()
        assert SInt32() != UInt32()

        assert SInt8() != Int8()
        assert UInt8() != Int8()
        assert SInt64() != Int64()
        assert UInt64() != Int64()

    def test_equality_self(self):
        """SIntN == SIntN, etc."""
        assert SInt32() == SInt32()
        assert UInt32() == UInt32()
        assert SInt64() == SInt64()
        assert UInt64() == UInt64()

    def test_sizes(self):
        """Signed/unsigned types should have the same size as their parent."""
        assert SInt8().size == Int8().size == 1
        assert UInt8().size == 1
        assert SInt16().size == Int16().size == 2
        assert UInt16().size == 2
        assert SInt32().size == Int32().size == 4
        assert UInt32().size == 4
        assert SInt64().size == Int64().size == 8
        assert UInt64().size == 8

    def test_repr(self):
        """Repr strings should indicate signedness."""
        assert "sint32" in repr(SInt32())
        assert "uint32" in repr(UInt32())
        assert "sint64" in repr(SInt64())
        assert "uint64" in repr(UInt64())
        assert "sint8" in repr(SInt8())
        assert "uint8" in repr(UInt8())

    def test_factory_functions(self):
        """Factory functions should return correct types."""
        assert type(signed_int_type(8)) is SInt8
        assert type(signed_int_type(16)) is SInt16
        assert type(signed_int_type(32)) is SInt32
        assert type(signed_int_type(64)) is SInt64

        assert type(unsigned_int_type(8)) is UInt8
        assert type(unsigned_int_type(16)) is UInt16
        assert type(unsigned_int_type(32)) is UInt32
        assert type(unsigned_int_type(64)) is UInt64

    def test_factory_fallback(self):
        """Factory functions should fall back to int_type for unsupported sizes."""
        assert type(signed_int_type(128)) is type(int_type(128))
        assert type(unsigned_int_type(128)) is type(int_type(128))


class TestLattice(unittest.TestCase):
    """Test the type lattice structure with signed/unsigned types."""

    def test_signed_unsigned_in_primitive_types(self):
        """All signed/unsigned singletons should be in PRIMITIVE_TYPES."""
        assert SInt8_ in PRIMITIVE_TYPES
        assert UInt8_ in PRIMITIVE_TYPES
        assert SInt16_ in PRIMITIVE_TYPES
        assert UInt16_ in PRIMITIVE_TYPES
        assert SInt32_ in PRIMITIVE_TYPES
        assert UInt32_ in PRIMITIVE_TYPES
        assert SInt64_ in PRIMITIVE_TYPES
        assert UInt64_ in PRIMITIVE_TYPES

    def test_lattice_64_edges_int32(self):
        """Int32 should have SInt32 and UInt32 as children in 64-bit lattice."""
        assert BASE_LATTICE_64.has_edge(Int32_, SInt32_)
        assert BASE_LATTICE_64.has_edge(Int32_, UInt32_)
        assert BASE_LATTICE_64.has_edge(SInt32_, Bottom_)
        assert BASE_LATTICE_64.has_edge(UInt32_, Bottom_)

    def test_lattice_64_edges_int64(self):
        """Int64 should have SInt64 and UInt64 as children in 64-bit lattice."""
        assert BASE_LATTICE_64.has_edge(Int64_, SInt64_)
        assert BASE_LATTICE_64.has_edge(Int64_, UInt64_)
        assert BASE_LATTICE_64.has_edge(SInt64_, Bottom_)
        assert BASE_LATTICE_64.has_edge(UInt64_, Bottom_)

    def test_lattice_64_edges_int8(self):
        """Int8 should have SInt8 and UInt8 as children in 64-bit lattice."""
        assert BASE_LATTICE_64.has_edge(Int8_, SInt8_)
        assert BASE_LATTICE_64.has_edge(Int8_, UInt8_)
        assert BASE_LATTICE_64.has_edge(SInt8_, Bottom_)
        assert BASE_LATTICE_64.has_edge(UInt8_, Bottom_)

    def test_lattice_64_edges_int16(self):
        """Int16 should have SInt16 and UInt16 as children in 64-bit lattice."""
        assert BASE_LATTICE_64.has_edge(Int16_, SInt16_)
        assert BASE_LATTICE_64.has_edge(Int16_, UInt16_)
        assert BASE_LATTICE_64.has_edge(SInt16_, Bottom_)
        assert BASE_LATTICE_64.has_edge(UInt16_, Bottom_)

    def test_lattice_32_edges(self):
        """32-bit lattice should also have signed/unsigned children."""
        assert BASE_LATTICE_32.has_edge(Int32_, SInt32_)
        assert BASE_LATTICE_32.has_edge(Int32_, UInt32_)
        assert BASE_LATTICE_32.has_edge(Int64_, SInt64_)
        assert BASE_LATTICE_32.has_edge(Int64_, UInt64_)
        assert BASE_LATTICE_32.has_edge(Int8_, SInt8_)
        assert BASE_LATTICE_32.has_edge(Int8_, UInt8_)
        assert BASE_LATTICE_32.has_edge(Int16_, SInt16_)
        assert BASE_LATTICE_32.has_edge(Int16_, UInt16_)

    def test_lattice_no_direct_intN_to_bottom_64(self):
        """In 64-bit lattice, IntN should NOT have a direct edge to Bottom (goes through signed/unsigned)."""
        assert not BASE_LATTICE_64.has_edge(Int8_, Bottom_)
        assert not BASE_LATTICE_64.has_edge(Int16_, Bottom_)
        assert not BASE_LATTICE_64.has_edge(Int32_, Bottom_)
        # Int64 still has edge to Pointer64 which goes to Bottom, but no direct edge
        assert not BASE_LATTICE_64.has_edge(Int64_, Bottom_)

    def test_lattice_no_direct_intN_to_bottom_32(self):
        """In 32-bit lattice, IntN should NOT have a direct edge to Bottom."""
        assert not BASE_LATTICE_32.has_edge(Int8_, Bottom_)
        assert not BASE_LATTICE_32.has_edge(Int16_, Bottom_)
        assert not BASE_LATTICE_32.has_edge(Int64_, Bottom_)

    def test_lattice_join_signed_unsigned(self):
        """The LCA (join) of SInt32 and UInt32 should be Int32."""
        # In the lattice, both SInt32 and UInt32 are children of Int32
        # so their common ancestor is Int32
        ancestors_s = networkx.ancestors(BASE_LATTICE_64, SInt32_) | {SInt32_}
        ancestors_u = networkx.ancestors(BASE_LATTICE_64, UInt32_) | {UInt32_}
        common = ancestors_s & ancestors_u
        assert Int32_ in common

    def test_lattice_meet_int_signed(self):
        """SInt32 is reachable from Int32 (meet of Int32 and SInt32 is SInt32)."""
        assert networkx.has_path(BASE_LATTICE_64, Int32_, SInt32_)
        assert networkx.has_path(BASE_LATTICE_64, Int32_, UInt32_)


class TestTranslator(unittest.TestCase):
    """Test translation between signed/unsigned type constants and SimTypes."""

    def setUp(self):
        self.arch = archinfo.ArchAMD64()
        self.translator = TypeTranslator(self.arch)

    def test_sint32_to_simtype(self):
        """SInt32 should translate to SimTypeInt(signed=True)."""
        st, _ = self.translator.tc2simtype(SInt32())
        assert isinstance(st, SimTypeInt)
        assert st.signed is True

    def test_uint32_to_simtype(self):
        """UInt32 should translate to SimTypeInt(signed=False)."""
        st, _ = self.translator.tc2simtype(UInt32())
        assert isinstance(st, SimTypeInt)
        assert st.signed is False

    def test_sint64_to_simtype(self):
        """SInt64 should translate to SimTypeLongLong(signed=True)."""
        st, _ = self.translator.tc2simtype(SInt64())
        assert isinstance(st, SimTypeLongLong)
        assert st.signed is True

    def test_uint64_to_simtype(self):
        """UInt64 should translate to SimTypeLongLong(signed=False)."""
        st, _ = self.translator.tc2simtype(UInt64())
        assert isinstance(st, SimTypeLongLong)
        assert st.signed is False

    def test_sint16_to_simtype(self):
        """SInt16 should translate to SimTypeShort(signed=True)."""
        st, _ = self.translator.tc2simtype(SInt16())
        assert isinstance(st, SimTypeShort)
        assert st.signed is True

    def test_uint16_to_simtype(self):
        """UInt16 should translate to SimTypeShort(signed=False)."""
        st, _ = self.translator.tc2simtype(UInt16())
        assert isinstance(st, SimTypeShort)
        assert st.signed is False

    def test_sint8_to_simtype(self):
        """SInt8 should translate to SimTypeChar(signed=True)."""
        st, _ = self.translator.tc2simtype(SInt8())
        assert isinstance(st, SimTypeChar)
        assert st.signed is True

    def test_uint8_to_simtype(self):
        """UInt8 should translate to SimTypeChar(signed=False)."""
        st, _ = self.translator.tc2simtype(UInt8())
        assert isinstance(st, SimTypeChar)
        assert st.signed is False

    def test_simtype_to_sint32(self):
        """SimTypeInt(signed=True) should translate to SInt32."""
        st = SimTypeInt(signed=True).with_arch(self.arch)
        tc = self.translator.simtype2tc(st)
        assert type(tc) is SInt32

    def test_simtype_to_uint32(self):
        """SimTypeInt(signed=False) should translate to UInt32."""
        st = SimTypeInt(signed=False).with_arch(self.arch)
        tc = self.translator.simtype2tc(st)
        assert type(tc) is UInt32

    def test_simtype_to_sint64(self):
        """SimTypeLongLong(signed=True) should translate to SInt64."""
        st = SimTypeLongLong(signed=True).with_arch(self.arch)
        tc = self.translator.simtype2tc(st)
        assert type(tc) is SInt64

    def test_simtype_to_uint64(self):
        """SimTypeLongLong(signed=False) should translate to UInt64."""
        st = SimTypeLongLong(signed=False).with_arch(self.arch)
        tc = self.translator.simtype2tc(st)
        assert type(tc) is UInt64

    def test_int32_still_translates(self):
        """Plain Int32 should still translate to SimTypeInt (unsigned, like before)."""
        st, _ = self.translator.tc2simtype(Int32())
        assert isinstance(st, SimTypeInt)
        assert st.signed is False


if __name__ == "__main__":
    unittest.main()
