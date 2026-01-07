#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Integration tests for enum types in decompiler and calling conventions."""
from __future__ import annotations

import os
import unittest

import angr
from angr.sim_type import (
    SimTypeEnum,
    SimTypeBitfield,
    SimTypeInt,
    SimTypeLong,
    SimTypeFunction,
    SimTypePointer,
    SimTypeChar,
    TypeRef,
)
from angr.calling_conventions import SimCCSystemVAMD64


TEST_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "..",
    "..",
)


class TestEnumCallingConvention(unittest.TestCase):
    """Test enum types in calling conventions."""

    def test_enum_classified_as_integer_amd64(self):
        """Test that SimTypeEnum is classified as INTEGER in AMD64 System V ABI."""
        import archinfo

        arch = archinfo.ArchAMD64()
        cc = SimCCSystemVAMD64(arch)

        enum = SimTypeEnum(
            members={"A": 0, "B": 1, "C": 2},
            name="test_enum",
        )
        enum = enum.with_arch(arch)

        # _classify should return INTEGER for enum types
        result = cc._classify(enum)
        assert result == ["INTEGER"]

    def test_bitfield_classified_as_integer_amd64(self):
        """Test that SimTypeBitfield is classified as INTEGER in AMD64 System V ABI."""
        import archinfo

        arch = archinfo.ArchAMD64()
        cc = SimCCSystemVAMD64(arch)

        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2, "EXEC": 4},
            name="prot_flags",
        )
        bf = bf.with_arch(arch)

        result = cc._classify(bf)
        assert result == ["INTEGER"]

    def test_enum_in_function_args_no_recursion(self):
        """Test that enum types in function prototypes don't cause recursion."""
        import archinfo

        arch = archinfo.ArchAMD64()
        cc = SimCCSystemVAMD64(arch)

        enum = SimTypeEnum(
            members={"STDIN": 0, "STDOUT": 1, "STDERR": 2},
            name="stdio_fd",
        )

        proto = SimTypeFunction(
            args=[enum, SimTypePointer(SimTypeChar()), SimTypeInt()],
            returnty=SimTypeInt(),
        )
        proto = proto.with_arch(arch)

        # This should not raise RecursionError
        args = cc.arg_locs(proto)
        assert len(args) == 3


class TestEnumDecompilerIntegration(unittest.TestCase):
    """Test enum types in decompiler output."""

    @unittest.skipUnless(
        os.path.exists(os.path.join(TEST_LOCATION, "fauxware")),
        "fauxware binary not found",
    )
    def test_enum_rendering_in_decompiler(self):
        """Test that enum values are rendered as member names in decompiled code."""
        proj = angr.Project(
            os.path.join(TEST_LOCATION, "fauxware"),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFGFast(normalize=True)

        # Create STDIO enum
        stdio_enum = SimTypeEnum(
            members={"STDIN_FILENO": 0, "STDOUT_FILENO": 1, "STDERR_FILENO": 2},
            name="stdio_fd",
        )
        proj.kb.types["stdio_fd"] = TypeRef("stdio_fd", stdio_enum)

        # Find read function and set prototype with enum
        read_func = proj.kb.functions.function(name="read")
        if read_func:
            read_func.prototype = SimTypeFunction(
                args=[stdio_enum, SimTypePointer(SimTypeChar()), SimTypeInt()],
                returnty=SimTypeInt(),
            )
            read_func.prototype = read_func.prototype.with_arch(proj.arch)

            # Decompile main
            main_func = proj.kb.functions.function(name="main")
            dec = proj.analyses.Decompiler(main_func)

            # Check that enum member name appears in output
            assert dec.codegen is not None
            output = dec.codegen.text
            assert "STDIN_FILENO" in output

    @unittest.skipUnless(
        os.path.exists(os.path.join(TEST_LOCATION, "fauxware")),
        "fauxware binary not found",
    )
    def test_prototype_preserved_after_decompilation(self):
        """Test that user-defined prototypes are preserved during decompilation."""
        proj = angr.Project(
            os.path.join(TEST_LOCATION, "fauxware"),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFGFast(normalize=True)

        # Create enum and set prototype
        stdio_enum = SimTypeEnum(
            members={"STDIN_FILENO": 0},
            name="stdio_fd",
        )

        read_func = proj.kb.functions.function(name="read")
        if read_func:
            original_proto = SimTypeFunction(
                args=[stdio_enum, SimTypePointer(SimTypeChar()), SimTypeInt()],
                returnty=SimTypeInt(),
            )
            original_proto = original_proto.with_arch(proj.arch)
            read_func.prototype = original_proto

            # Decompile main (which calls read)
            main_func = proj.kb.functions.function(name="main")
            proj.analyses.Decompiler(main_func)

            # Check that prototype is preserved
            assert read_func.prototype is not None
            assert isinstance(read_func.prototype.args[0], SimTypeEnum)


class TestEnumKnowledgeBaseIntegration(unittest.TestCase):
    """Test enum types with knowledge base types store."""

    def test_enum_store_and_retrieve(self):
        """Test storing and retrieving enum from kb.types."""
        proj = angr.Project(
            os.path.join(TEST_LOCATION, "fauxware"),
            auto_load_libs=False,
        )

        enum = SimTypeEnum(
            members={"A": 0, "B": 1, "C": 2},
            name="test_enum",
        )
        proj.kb.types["test_enum"] = TypeRef("test_enum", enum)

        # Retrieve and verify
        retrieved = proj.kb.types["test_enum"]
        assert retrieved.name == "test_enum"
        assert isinstance(retrieved.type, SimTypeEnum)
        assert retrieved.type.resolve(0) == "A"
        assert retrieved.type.resolve(1) == "B"

    def test_bitfield_store_and_retrieve(self):
        """Test storing and retrieving bitfield from kb.types."""
        proj = angr.Project(
            os.path.join(TEST_LOCATION, "fauxware"),
            auto_load_libs=False,
        )

        bf = SimTypeBitfield(
            flags={"READ": 1, "WRITE": 2, "EXEC": 4},
            name="prot_flags",
        )
        proj.kb.types["prot_flags"] = TypeRef("prot_flags", bf)

        # Retrieve and verify
        retrieved = proj.kb.types["prot_flags"]
        assert retrieved.name == "prot_flags"
        assert isinstance(retrieved.type, SimTypeBitfield)
        flags, unknown = retrieved.type.resolve(3)
        assert set(flags) == {"READ", "WRITE"}
        assert unknown == 0


if __name__ == "__main__":
    unittest.main()
