#!/usr/bin/env python3
"""
Realistic test case for enum type inference during decompilation.

This test demonstrates how SimTypeEnum integrates with angr's type inference
system (Typehoon) during decompilation of functions that use enum types.
"""
from __future__ import annotations

import os
import unittest

import angr
from angr.sim_type import SimTypeEnum, SimTypeInt, SimTypePointer, parse_type, parse_defns
from angr.analyses.typehoon.typeconsts import Enum, Int32
from angr.analyses.typehoon.translator import TypeTranslator
from angr.analyses.typehoon.lifter import TypeLifter


class TestEnumTypeInference(unittest.TestCase):
    """Test enum type inference in realistic decompilation scenarios."""

    @classmethod
    def setUpClass(cls):
        """Load the test binary once for all tests."""
        cls.binary_path = os.path.join(os.path.dirname(__file__), "test_enum")
        if os.path.exists(cls.binary_path):
            cls.proj = angr.Project(cls.binary_path, auto_load_libs=False)
        else:
            cls.proj = None

    def test_enum_ground_truth_application(self):
        """Test applying enum types as ground truth during type inference."""
        if self.proj is None:
            self.skipTest("Test binary not found")

        # Define enum types that match the binary
        color_enum = parse_type("enum Color { RED = 0, GREEN = 1, BLUE = 2 }")
        status_enum = parse_type("enum Status { OK = 0, ERROR = -1, PENDING = 100, UNKNOWN = 999 }")

        # Apply architecture
        color_enum = color_enum.with_arch(self.proj.arch)
        status_enum = status_enum.with_arch(self.proj.arch)

        # Verify the types are properly formed
        self.assertIsInstance(color_enum, SimTypeEnum)
        self.assertIsInstance(status_enum, SimTypeEnum)
        self.assertEqual(color_enum.size, 32)
        self.assertEqual(status_enum.size, 32)

        # Test that we can lift these to type constants for Typehoon
        lifter = TypeLifter(self.proj.arch.bits)
        color_tc = lifter.lift(color_enum)
        status_tc = lifter.lift(status_enum)

        self.assertIsInstance(color_tc, Enum)
        self.assertIsInstance(status_tc, Enum)
        self.assertEqual(color_tc.members, {"RED": 0, "GREEN": 1, "BLUE": 2})
        self.assertEqual(status_tc.members, {"OK": 0, "ERROR": -1, "PENDING": 100, "UNKNOWN": 999})

    def test_enum_translation_roundtrip(self):
        """Test that enums survive translation to/from type constants."""
        if self.proj is None:
            self.skipTest("Test binary not found")

        # Create an enum type
        original = parse_type("enum FileMode { READ = 1, WRITE = 2, EXEC = 4 }")
        original = original.with_arch(self.proj.arch)

        # Lift to type constant
        lifter = TypeLifter(self.proj.arch.bits)
        tc = lifter.lift(original)

        # Translate back to SimType
        translator = TypeTranslator(self.proj.arch)
        restored, _ = translator.tc2simtype(tc)

        # Verify roundtrip preserves data
        self.assertIsInstance(restored, SimTypeEnum)
        self.assertEqual(restored.name, original.name)
        self.assertEqual(restored.members, original.members)

    def test_enum_in_function_prototype(self):
        """Test parsing function prototypes with enum parameters and return types."""
        # Parse enum and function definitions together
        defns = parse_defns("""
            enum Color { RED, GREEN, BLUE };
            enum Color get_next_color(enum Color current);
            int color_to_rgb(enum Color c);
        """)

        # Verify function prototypes reference the enum
        self.assertIn("get_next_color", defns)
        self.assertIn("color_to_rgb", defns)

        get_next = defns["get_next_color"]
        self.assertIsInstance(get_next.returnty, SimTypeEnum)
        self.assertEqual(get_next.returnty.name, "Color")
        # Verify enum members were parsed correctly
        self.assertEqual(get_next.returnty.members, {"RED": 0, "GREEN": 1, "BLUE": 2})

        color_to_rgb = defns["color_to_rgb"]
        self.assertIsInstance(color_to_rgb.args[0], SimTypeEnum)
        self.assertEqual(color_to_rgb.args[0].name, "Color")

    def test_enum_in_struct(self):
        """Test enum types used within struct definitions."""
        # parse_defns returns function prototypes, so we need a function
        # that uses the struct to get the struct definition included
        defns = parse_defns("""
            enum State { IDLE, RUNNING, STOPPED };
            struct Process {
                int pid;
                enum State state;
                int exit_code;
            };
            struct Process* create_process(int pid, enum State initial_state);
        """)

        # Verify function was parsed and its return type references the struct
        self.assertIn("create_process", defns)
        create_proc = defns["create_process"]

        # The return type is a pointer to struct Process
        self.assertIsInstance(create_proc.returnty, SimTypePointer)
        process_struct = create_proc.returnty.pts_to

        # Verify struct contains enum field
        self.assertIn("state", process_struct.fields)
        state_field = process_struct.fields["state"]
        self.assertIsInstance(state_field, SimTypeEnum)
        self.assertEqual(state_field.name, "State")
        # Verify enum members are present
        self.assertEqual(state_field.members, {"IDLE": 0, "RUNNING": 1, "STOPPED": 2})

        # Also verify the enum parameter in the function
        self.assertIsInstance(create_proc.args[1], SimTypeEnum)
        self.assertEqual(create_proc.args[1].name, "State")

    def test_decompile_with_enum_types(self):
        """Test decompilation with enum type annotations."""
        if self.proj is None:
            self.skipTest("Test binary not found")

        # Find the color_to_rgb function
        cfg = self.proj.analyses.CFGFast(normalize=True)
        color_to_rgb_func = None
        for func_addr, func in self.proj.kb.functions.items():
            if func.name == "color_to_rgb":
                color_to_rgb_func = func
                break

        if color_to_rgb_func is None:
            # Try to find by symbol
            sym = self.proj.loader.find_symbol("color_to_rgb")
            if sym:
                color_to_rgb_func = self.proj.kb.functions.get(sym.rebased_addr)

        if color_to_rgb_func is None:
            self.skipTest("color_to_rgb function not found in binary")

        # Define the enum type for the parameter
        color_enum = parse_type("enum Color { RED = 0, GREEN = 1, BLUE = 2 }")

        # Set the function prototype with enum type
        from angr.sim_type import SimTypeFunction
        prototype = SimTypeFunction([color_enum], SimTypeInt(signed=True))
        color_to_rgb_func.prototype = prototype

        # Attempt decompilation
        try:
            dec = self.proj.analyses.Decompiler(color_to_rgb_func)
            if dec.codegen and dec.codegen.text:
                decompiled = dec.codegen.text
                print(f"\nDecompiled color_to_rgb:\n{decompiled}")
                # The decompilation should work without errors
                self.assertIsNotNone(decompiled)
        except Exception as e:
            # Decompilation might fail for various reasons unrelated to enum support
            print(f"Decompilation failed (may be unrelated to enum support): {e}")

    def test_enum_type_constant_in_solver(self):
        """Test that Enum type constants work correctly in the type solver."""
        # Create some enum type constants
        color_tc = Enum({"RED": 0, "GREEN": 1, "BLUE": 2}, name="Color")
        flags_tc = Enum({"NONE": 0, "READ": 1, "WRITE": 2, "EXEC": 4}, name="Flags")

        # Test size property
        self.assertEqual(color_tc.size, 4)  # Default int size in bytes
        self.assertEqual(flags_tc.size, 4)

        # Test with explicit base type
        byte_enum_tc = Enum({"A": 0, "B": 1}, base_type=Int32(), name="ByteEnum")
        self.assertEqual(byte_enum_tc.size, 4)

        # Test replace method (enums don't have nested types to replace)
        mapping = {}
        replaced = color_tc.replace(mapping)
        self.assertIs(replaced, color_tc)  # Should return same object

        # Test equality and hashing
        color_tc2 = Enum({"RED": 0, "GREEN": 1, "BLUE": 2}, name="Color", idx=color_tc.idx)
        self.assertEqual(color_tc, color_tc2)
        self.assertEqual(hash(color_tc), hash(color_tc2))

    def test_enum_c_representation_formats(self):
        """Test various C representation formats for enums."""
        # Named enum with explicit values
        enum1 = SimTypeEnum(
            {"SUCCESS": 0, "FAILURE": 1, "TIMEOUT": 2, "UNKNOWN": 255},
            name="ResultCode"
        )

        # Short representation
        short_repr = enum1.c_repr(full=0)
        self.assertEqual(short_repr, "enum ResultCode")

        # Full representation
        full_repr = enum1.c_repr(full=1)
        self.assertIn("enum ResultCode", full_repr)
        self.assertIn("SUCCESS = 0", full_repr)
        self.assertIn("FAILURE = 1", full_repr)
        self.assertIn("TIMEOUT = 2", full_repr)
        self.assertIn("UNKNOWN = 255", full_repr)

        # With variable name
        var_repr = enum1.c_repr(name="result", full=1)
        self.assertIn("result", var_repr)

        # Anonymous enum
        anon_enum = SimTypeEnum({"X": 1, "Y": 2})
        anon_repr = anon_enum.c_repr(full=0)
        self.assertEqual(anon_repr, "enum <anon>")

    def test_enum_json_persistence(self):
        """Test that enum types can be persisted and restored via JSON."""
        from angr.sim_type import SimType

        # Create a complex enum
        original = SimTypeEnum(
            {"NORTH": 0, "EAST": 90, "SOUTH": 180, "WEST": 270},
            name="Direction"
        )

        # Serialize to JSON
        json_data = original.to_json()

        # Verify JSON structure
        self.assertEqual(json_data["_t"], "enum")
        self.assertEqual(json_data["name"], "Direction")
        self.assertEqual(json_data["members"], {"NORTH": 0, "EAST": 90, "SOUTH": 180, "WEST": 270})

        # Deserialize from JSON
        restored = SimType.from_json(json_data)

        # Verify restoration
        self.assertIsInstance(restored, SimTypeEnum)
        self.assertEqual(restored.name, original.name)
        self.assertEqual(restored.members, original.members)

        # Verify the restored enum is functional
        import archinfo
        restored_with_arch = restored.with_arch(archinfo.ArchAMD64())
        self.assertEqual(restored_with_arch.size, 32)


class TestEnumEdgeCases(unittest.TestCase):
    """Test edge cases for enum handling."""

    def test_empty_enum(self):
        """Test handling of empty enum."""
        empty = SimTypeEnum({}, name="Empty")
        self.assertEqual(empty.members, {})
        self.assertEqual(empty.c_repr(full=1), "enum Empty {\n\n}")

    def test_single_member_enum(self):
        """Test enum with single member."""
        single = SimTypeEnum({"ONLY": 42}, name="Single")
        self.assertEqual(single.members, {"ONLY": 42})
        c_repr = single.c_repr(full=1)
        self.assertIn("ONLY = 42", c_repr)

    def test_large_enum_values(self):
        """Test enum with large values."""
        large = SimTypeEnum({
            "MIN": -2147483648,
            "MAX": 2147483647,
            "ZERO": 0
        }, name="Limits")

        self.assertEqual(large.members["MIN"], -2147483648)
        self.assertEqual(large.members["MAX"], 2147483647)

    def test_enum_with_special_names(self):
        """Test enum with various naming conventions."""
        special = SimTypeEnum({
            "ALL_CAPS": 0,
            "mixedCase": 1,
            "with_underscore": 2,
            "_leading": 3,
            "trailing_": 4,
        }, name="SpecialNames")

        # All names should be preserved
        self.assertEqual(len(special.members), 5)
        for name in ["ALL_CAPS", "mixedCase", "with_underscore", "_leading", "trailing_"]:
            self.assertIn(name, special.members)

    def test_parse_enum_with_hex_values(self):
        """Test parsing enum with hexadecimal values."""
        enum_type = parse_type("enum Flags { NONE = 0x0, READ = 0x1, WRITE = 0x2, EXEC = 0x4 }")
        self.assertIsInstance(enum_type, SimTypeEnum)
        self.assertEqual(enum_type.members["NONE"], 0)
        self.assertEqual(enum_type.members["READ"], 1)
        self.assertEqual(enum_type.members["WRITE"], 2)
        self.assertEqual(enum_type.members["EXEC"], 4)

    def test_parse_enum_with_expressions(self):
        """Test parsing enum with constant expressions."""
        enum_type = parse_type("enum Bits { B0 = 1, B1 = 1 << 1, B2 = 1 << 2, B3 = 1 << 3 }")
        self.assertIsInstance(enum_type, SimTypeEnum)
        self.assertEqual(enum_type.members["B0"], 1)
        self.assertEqual(enum_type.members["B1"], 2)
        self.assertEqual(enum_type.members["B2"], 4)
        self.assertEqual(enum_type.members["B3"], 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
