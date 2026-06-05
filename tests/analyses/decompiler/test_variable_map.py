#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import json
import unittest

from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import SimTypeChar, SimTypePointer
from angr.sim_variable import SimRegisterVariable, SimStackVariable


class _FakeConst:
    """A stand-in for an AIL Const expression that only exposes ``.idx``."""

    def __init__(self, idx):
        self.idx = idx


class _FakeBinOp:
    """A stand-in for a different AIL expression class that shares an ``.idx`` with a _FakeConst."""

    def __init__(self, idx):
        self.idx = idx


class TestVariableMap(unittest.TestCase):
    def test_set_and_get(self):
        vm = VariableMap()
        atom = _FakeConst(7)
        var = SimRegisterVariable(8, 8, ident="reg_1")

        vm.set_variable(atom, var, 4)

        assert vm.variable(atom) is var
        assert vm.variable_offset(atom) == 4
        assert vm.has_variable(atom)
        # a freshly-constructed equal object resolves to the same entry (keyed by idx + class)
        assert vm.variable(_FakeConst(7)) is var

    def test_idx_collision_between_classes(self):
        # AIL reuses .idx across distinct objects; objects of different classes that share an idx must NOT be
        # conflated.
        vm = VariableMap()
        const = _FakeConst(11666)
        binop = _FakeBinOp(11666)
        var = SimRegisterVariable(8, 8, ident="reg_const")

        vm.set_variable(const, var, 0)

        assert vm.variable(const) is var
        assert vm.variable(binop) is None
        assert not vm.has_variable(binop)

    def test_defaults_for_missing_keys(self):
        vm = VariableMap()
        missing = _FakeConst(123)
        assert vm.variable(missing) is None
        assert vm.variable_offset(missing) == 0
        assert vm.custom_string(missing) is False
        assert vm.reference_values(missing) is None
        assert vm.reference_variable(missing) is None
        assert vm.reference_variable_offset(missing) == 0
        assert not vm.has_variable(missing)

    def test_custom_string_and_reference_variable(self):
        vm = VariableMap()
        a, b = _FakeConst(1), _FakeConst(2)
        vm.set_custom_string(a)
        ref_var = SimStackVariable(-0x10, 8, ident="stack_2")
        vm.set_reference_variable(b, ref_var, 3)

        assert vm.custom_string(a) is True
        assert vm.reference_variable(b) is ref_var
        assert vm.reference_variable_offset(b) == 3

    def test_transfer(self):
        vm = VariableMap()
        src = _FakeConst(1)
        dst = _FakeConst(2)
        var = SimRegisterVariable(8, 8, ident="reg_1")
        vm.set_variable(src, var, 4)
        vm.set_custom_string(src)

        vm.transfer(src, dst)

        assert vm.variable(dst) is var
        assert vm.variable_offset(dst) == 4
        assert vm.custom_string(dst) is True

    def test_json_round_trip(self):
        vm = VariableMap()
        v1 = SimRegisterVariable(8, 8, ident="reg_1")
        v2 = SimStackVariable(-0x10, 8, ident="stack_2")
        a, b, c, d, e = _FakeConst(1), _FakeConst(2), _FakeConst(3), _FakeConst(4), _FakeConst(5)
        vm.set_variable(a, v1, 0)
        vm.set_variable(b, v2, 8)
        vm.set_custom_string(c)
        vm.set_reference_variable(d, v2, 2)
        char_ptr = SimTypePointer(SimTypeChar())
        vm.set_reference_values(e, {char_ptr: "hello"})

        blob = json.dumps(vm.to_json())
        data = json.loads(blob)

        idents = {"reg_1": v1, "stack_2": v2}
        restored = VariableMap.from_json(data, idents.get)

        assert restored.variable(a) is v1
        assert restored.variable_offset(a) == 0
        assert restored.variable(b) is v2
        assert restored.variable_offset(b) == 8
        assert restored.custom_string(c) is True
        assert restored.reference_variable(d) is v2
        assert restored.reference_variable_offset(d) == 2

        ref_vals = restored.reference_values(e)
        assert ref_vals is not None
        assert len(ref_vals) == 1
        (ty, val) = next(iter(ref_vals.items()))
        assert isinstance(ty, SimTypePointer)
        assert val == "hello"


if __name__ == "__main__":
    unittest.main()
