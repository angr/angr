#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import json
import unittest

from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import SimTypeChar, SimTypePointer
from angr.sim_variable import SimRegisterVariable, SimStackVariable


class _FakeAtom:
    """A stand-in for an AIL Statement/Expression that only exposes ``.idx``."""

    def __init__(self, idx):
        self.idx = idx


class TestVariableMap(unittest.TestCase):
    def test_set_and_get_by_object_and_idx(self):
        vm = VariableMap()
        atom = _FakeAtom(7)
        var = SimRegisterVariable(8, 8, ident="reg_1")

        vm.set_variable(atom, var, 4)

        # access by object
        assert vm.variable(atom) is var
        assert vm.variable_offset(atom) == 4
        # access by idx directly
        assert vm.variable(7) is var
        assert vm.variable_offset(7) == 4
        assert vm.has_variable(7)

    def test_defaults_for_missing_keys(self):
        vm = VariableMap()
        assert vm.variable(123) is None
        assert vm.variable_offset(123) == 0
        assert vm.custom_string(123) is False
        assert vm.reference_values(123) is None
        assert vm.reference_variable(123) is None
        assert vm.reference_variable_offset(123) == 0
        assert not vm.has_variable(123)

    def test_custom_string_and_reference_variable(self):
        vm = VariableMap()
        vm.set_custom_string(1)
        ref_var = SimStackVariable(-0x10, 8, ident="stack_2")
        vm.set_reference_variable(2, ref_var, 3)

        assert vm.custom_string(1) is True
        assert vm.reference_variable(2) is ref_var
        assert vm.reference_variable_offset(2) == 3

    def test_transfer(self):
        vm = VariableMap()
        var = SimRegisterVariable(8, 8, ident="reg_1")
        vm.set_variable(1, var, 4)
        vm.set_custom_string(1)

        vm.transfer(1, 2)

        assert vm.variable(2) is var
        assert vm.variable_offset(2) == 4
        assert vm.custom_string(2) is True

    def test_json_round_trip(self):
        vm = VariableMap()
        v1 = SimRegisterVariable(8, 8, ident="reg_1")
        v2 = SimStackVariable(-0x10, 8, ident="stack_2")
        vm.set_variable(1, v1, 0)
        vm.set_variable(2, v2, 8)
        vm.set_custom_string(3)
        vm.set_reference_variable(4, v2, 2)
        char_ptr = SimTypePointer(SimTypeChar())
        vm.set_reference_values(5, {char_ptr: "hello"})

        # ensure the result is JSON-serializable
        blob = json.dumps(vm.to_json())
        data = json.loads(blob)

        idents = {"reg_1": v1, "stack_2": v2}
        restored = VariableMap.from_json(data, idents.get)

        assert restored.variable(1) is v1
        assert restored.variable_offset(1) == 0
        assert restored.variable(2) is v2
        assert restored.variable_offset(2) == 8
        assert restored.custom_string(3) is True
        assert restored.reference_variable(4) is v2
        assert restored.reference_variable_offset(4) == 2

        ref_vals = restored.reference_values(5)
        assert ref_vals is not None
        assert len(ref_vals) == 1
        (ty, val) = next(iter(ref_vals.items()))
        assert isinstance(ty, SimTypePointer)
        assert val == "hello"


if __name__ == "__main__":
    unittest.main()
