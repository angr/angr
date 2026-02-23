#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

import os
import unittest

import archinfo
import angr
from angr.calling_conventions import SimCCSystemVAMD64
from angr.sim_type import SimType, SimTypeEnum, SimTypeInt, SimTypePointer, parse_type, parse_defns, SimTypeFunction
from angr.analyses.typehoon.typeconsts import Enum, Int32
from angr.analyses.typehoon.translator import TypeTranslator

from tests.common import bin_location, print_decompilation_result


class TestEnumTypeInference(unittest.TestCase):
    """Test enum type inference during decompilation."""

    @classmethod
    def setUpClass(cls):
        """Load the test binary once for all tests."""
        cls.binary_path = os.path.join(bin_location, "tests", "x86_64", "test_enum")
        cls.proj = angr.Project(cls.binary_path, auto_load_libs=False)

    def test_enum_ground_truth_application(self):
        """Test applying enum types as ground truth during type inference."""
        # Define enum types that match the binary
        color_enum = parse_type("enum Color { RED = 0, GREEN = 1, BLUE = 2 }")
        status_enum = parse_type("enum Status { OK = 0, ERROR = -1, PENDING = 100, UNKNOWN = 999 }")

        # Apply architecture
        color_enum = color_enum.with_arch(self.proj.arch)
        status_enum = status_enum.with_arch(self.proj.arch)

        # Verify the types are properly formed
        assert isinstance(color_enum, SimTypeEnum)
        assert isinstance(status_enum, SimTypeEnum)
        assert color_enum.size == 32
        assert status_enum.size == 32

        # Test that we can lift these to type constants for Typehoon
        lifter = TypeTranslator(self.proj.arch.bits)
        color_tc = lifter.lift(color_enum)
        status_tc = lifter.lift(status_enum)

        assert isinstance(color_tc, Enum)
        assert isinstance(status_tc, Enum)
        assert color_tc.members == {"RED": 0, "GREEN": 1, "BLUE": 2}
        assert status_tc.members == {"OK": 0, "ERROR": -1, "PENDING": 100, "UNKNOWN": 999}

    def test_enum_translation_roundtrip(self):
        """Test that enums survive translation to/from type constants."""
        # Create an enum type
        original = parse_type("enum FileMode { READ = 1, WRITE = 2, EXEC = 4 }")
        original = original.with_arch(self.proj.arch)
        assert isinstance(original, SimTypeEnum)

        # Lift to type constant
        lifter = TypeTranslator(self.proj.arch.bits)
        tc = lifter.lift(original)

        # Translate back to SimType
        translator = TypeTranslator(self.proj.arch)
        restored, _ = translator.tc2simtype(tc)

        # Verify roundtrip preserves data
        assert isinstance(restored, SimTypeEnum)
        assert restored.name == original.name
        assert restored.members == original.members

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
        assert isinstance(get_next.returnty, SimTypeEnum)
        assert get_next.returnty.name == "Color"
        # Verify enum members were parsed correctly
        assert get_next.returnty.members == {"RED": 0, "GREEN": 1, "BLUE": 2}

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
        assert "create_process" in defns
        create_proc = defns["create_process"]

        # The return type is a pointer to struct Process
        assert isinstance(create_proc.returnty, SimTypePointer)
        process_struct = create_proc.returnty.pts_to

        # Verify struct contains enum field
        assert "state" in process_struct.fields
        state_field = process_struct.fields["state"]
        assert isinstance(state_field, SimTypeEnum)
        assert state_field.name == "State"
        # Verify enum members are present
        assert state_field.members == {"IDLE": 0, "RUNNING": 1, "STOPPED": 2}

        # Also verify the enum parameter in the function
        assert isinstance(create_proc.args[1], SimTypeEnum)
        assert create_proc.args[1].name == "State"

    def test_decompile_with_enum_types(self):
        # Find the color_to_rgb function
        cfg = self.proj.analyses.CFGFast(normalize=True)
        color_to_rgb_func = cfg.functions["color_to_rgb"]
        # Define the enum type for the parameter
        color_enum = parse_type("enum Color { RED = 0, GREEN = 1, BLUE = 2 }")

        prototype = SimTypeFunction([color_enum], SimTypeInt(signed=True))
        color_to_rgb_func.prototype = prototype
        color_to_rgb_func.calling_convention = SimCCSystemVAMD64(self.proj.arch)
        color_to_rgb_func.is_prototype_guessed = False

        # Attempt decompilation
        dec = self.proj.analyses.Decompiler(color_to_rgb_func)
        assert dec.codegen and dec.codegen.text
        print_decompilation_result(dec)

        assert "enum Color" in dec.codegen.text
        assert "== BLUE" in dec.codegen.text
        assert "== GREEN" in dec.codegen.text
        assert "RED" not in dec.codegen.text

    def test_enum_type_constant_in_solver(self):
        """Test that Enum type constants work correctly in the type solver."""
        # Create some enum type constants
        color_tc = Enum({"RED": 0, "GREEN": 1, "BLUE": 2}, name="Color")
        flags_tc = Enum({"NONE": 0, "READ": 1, "WRITE": 2, "EXEC": 4}, name="Flags")

        # Test size property
        assert color_tc.size == 4  # Default int size in bytes
        assert flags_tc.size == 4

        # Test with explicit base type
        byte_enum_tc = Enum({"A": 0, "B": 1}, base_type=Int32(), name="ByteEnum")
        assert byte_enum_tc.size == 4

        # Test replace method (enums don't have nested types to replace)
        mapping = {}
        replaced = color_tc.replace(mapping)
        assert replaced is color_tc  # Should return same object

        # Test equality and hashing
        color_tc2 = Enum({"RED": 0, "GREEN": 1, "BLUE": 2}, name="Color", idx=color_tc.idx)
        assert color_tc == color_tc2
        assert hash(color_tc) == hash(color_tc2)

    def test_enum_c_representation_formats(self):
        """Test various C representation formats for enums."""
        # Named enum with explicit values
        enum1 = SimTypeEnum({"SUCCESS": 0, "FAILURE": 1, "TIMEOUT": 2, "UNKNOWN": 255}, name="ResultCode")

        # Short representation
        short_repr = enum1.c_repr(full=0)
        assert short_repr == "enum ResultCode"

        # Full representation
        full_repr = enum1.c_repr(full=1)
        assert "enum ResultCode" in full_repr
        assert "SUCCESS = 0" in full_repr
        assert "FAILURE = 1" in full_repr
        assert "TIMEOUT = 2" in full_repr
        assert "UNKNOWN = 255" in full_repr

        # With variable name
        var_repr = enum1.c_repr(name="result", full=1)
        assert "result" in var_repr

        # Anonymous enum
        anon_enum = SimTypeEnum({"X": 1, "Y": 2})
        anon_repr = anon_enum.c_repr(full=0)
        assert anon_repr == "enum <anon>"

    def test_enum_json_persistence(self):
        """Test that enum types can be persisted and restored via JSON."""
        # Create a complex enum
        original = SimTypeEnum({"NORTH": 0, "EAST": 90, "SOUTH": 180, "WEST": 270}, name="Direction")

        # Serialize to JSON
        json_data = original.to_json()

        # Verify JSON structure
        assert json_data["_t"] == "enum"
        assert json_data["name"] == "Direction"
        assert json_data["members"] == {"NORTH": 0, "EAST": 90, "SOUTH": 180, "WEST": 270}

        # Deserialize from JSON
        restored = SimType.from_json(json_data)

        # Verify restoration
        assert isinstance(restored, SimTypeEnum)
        assert restored.name == original.name
        assert restored.members == original.members

        # Verify the restored enum is functional
        restored_with_arch = restored.with_arch(archinfo.ArchAMD64())
        assert restored_with_arch.size == 32


if __name__ == "__main__":
    unittest.main(verbosity=2)
