#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import json
import unittest
from typing import cast

from angr.ailment import Block, Manager
from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.analyses.decompiler.optimization_passes.return_duplicator_base import ReturnDuplicatorBase
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import SimTypeChar, SimTypePointer
from angr.sim_variable import SimConstantVariable, SimRegisterVariable, SimStackVariable


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

        # A VVar transfer uses the VVar namespace and must not copy colliding Const state.
        vvar = VirtualVariable(3, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        duplicate_vvar = VirtualVariable(4, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        const = Const(3, 0, 64)
        const_var = SimConstantVariable(8, value=0, ident="const_0")
        vm.set_variable(vvar, var, 5)
        vm.set_variable(const, const_var, 6)
        vm.set_custom_string(const)
        vm.transfer(vvar, duplicate_vvar)
        self.assertIs(vm.variable(duplicate_vvar), var)
        self.assertEqual(vm.variable_offset(duplicate_vvar), 5)
        self.assertFalse(vm.custom_string(duplicate_vvar))
        self.assertIsNone(vm.variable(Const(duplicate_vvar.idx, 0, 64)))

    def test_cross_varid_transfer_is_occurrence_local(self):
        vm = VariableMap()
        src = VirtualVariable(7, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        dst = VirtualVariable(8, 200, 64, VirtualVariableCategory.REGISTER, oident=24)
        src_var = SimRegisterVariable(16, 8, ident="reg_src")
        src_const = Const(src.idx, 0, 64)
        dst_const = Const(dst.idx, 1, 64)
        src_const_var = SimConstantVariable(8, value=0, ident="const_src")
        dst_const_var = SimConstantVariable(8, value=1, ident="const_dst")
        vm.set_variable(src, src_var, 3)
        vm.set_variable(src_const, src_const_var, 5)
        vm.set_variable(dst_const, dst_const_var, 6)
        vm.set_custom_string(src_const)

        vm.transfer(src, dst)

        self.assertIs(vm.variable(dst), src_var)
        self.assertEqual(vm.variable_offset(dst), 3)
        self.assertTrue(vm.has_variable(dst))
        fresh_dst_wrapper = VirtualVariable(10, 200, 64, VirtualVariableCategory.REGISTER, oident=24)
        self.assertIsNone(vm.variable(fresh_dst_wrapper))
        self.assertEqual(vm.variable_offset(fresh_dst_wrapper), 0)
        self.assertFalse(vm.has_variable(fresh_dst_wrapper))
        self.assertIs(vm.variable(src_const), src_const_var)
        self.assertIs(vm.variable(dst_const), dst_const_var)
        self.assertEqual(vm.variable_offset(dst_const), 6)
        self.assertTrue(vm.custom_string(src_const))
        self.assertFalse(vm.custom_string(dst_const))

        tombstoned_src = VirtualVariable(17, 101, 64, VirtualVariableCategory.REGISTER, oident=32)
        tombstoned_dst = VirtualVariable(18, 201, 64, VirtualVariableCategory.REGISTER, oident=40)
        dst_sibling = VirtualVariable(19, 201, 64, VirtualVariableCategory.REGISTER, oident=40)
        tombstoned_src_var = SimRegisterVariable(32, 8, ident="reg_tombstoned_src")
        dst_sibling_var = SimRegisterVariable(40, 8, ident="reg_dst_sibling")
        vm.set_variable(tombstoned_src, tombstoned_src_var, 7)
        vm.set_variable(tombstoned_src, None)
        vm.set_variable(dst_sibling, dst_sibling_var, 8)

        vm.transfer(tombstoned_src, tombstoned_dst)

        self.assertIsNone(vm.variable(tombstoned_dst))
        self.assertEqual(vm.variable_offset(tombstoned_dst), 0)
        self.assertFalse(vm.has_variable(tombstoned_dst))
        fresh_tombstone_wrapper = VirtualVariable(20, 201, 64, VirtualVariableCategory.REGISTER, oident=40)
        self.assertIs(vm.variable(fresh_tombstone_wrapper), dst_sibling_var)
        self.assertEqual(vm.variable_offset(fresh_tombstone_wrapper), 8)

    def test_return_duplicator_fresh_vvars_keep_occurrence_bindings(self):
        vm = VariableMap()
        manager = Manager()
        manager.variable_map = vm
        dst = VirtualVariable(7, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        ret_expr = VirtualVariable(9, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        dst_var = SimRegisterVariable(16, 8, ident="reg_dst")
        ret_var = SimRegisterVariable(24, 8, ident="reg_ret")
        vm.set_variable(dst, dst_var, 1)
        vm.set_variable(ret_expr, ret_var, 2)
        block = Block(
            0x400000,
            4,
            statements=[Assignment(1, dst, Const(8, 0, 64)), Return(2, [ret_expr])],
            idx=0,
        )

        copied_block = block.deep_copy(manager)
        copied_dst = cast(Assignment, copied_block.statements[0]).dst
        self.assertIsInstance(copied_dst, VirtualVariable)
        colliding_const = Const(copied_dst.idx, 1, 64)
        colliding_const_var = SimConstantVariable(8, value=1, ident="const_collision")
        vm.set_variable(colliding_const, colliding_const_var, 3)

        duplicator = object.__new__(ReturnDuplicatorBase)
        duplicator._manager = manager
        duplicator.vvar_id_start = 1000
        rewritten_block = duplicator._use_fresh_virtual_variables(copied_block, {})

        rewritten_assignment = cast(Assignment, rewritten_block.statements[0])
        rewritten_return = cast(Return, rewritten_block.statements[1])
        rewritten_dst = cast(VirtualVariable, rewritten_assignment.dst)
        rewritten_ret_expr = cast(VirtualVariable, rewritten_return.ret_exprs[0])
        self.assertEqual(rewritten_dst.varid, 1000)
        self.assertEqual(rewritten_ret_expr.varid, 1000)
        self.assertIs(vm.variable(rewritten_dst), dst_var)
        self.assertEqual(vm.variable_offset(rewritten_dst), 1)
        self.assertIs(vm.variable(rewritten_ret_expr), ret_var)
        self.assertEqual(vm.variable_offset(rewritten_ret_expr), 2)
        fresh_wrapper = VirtualVariable(99, 1000, 64, VirtualVariableCategory.REGISTER, oident=16)
        self.assertIsNone(vm.variable(fresh_wrapper))
        self.assertEqual(vm.variable_offset(fresh_wrapper), 0)
        self.assertFalse(vm.has_variable(fresh_wrapper))
        self.assertIs(vm.variable(colliding_const), colliding_const_var)
        self.assertEqual(vm.variable_offset(colliding_const), 3)

    def test_vvar_deep_copy_does_not_transfer_colliding_idx_mapping(self):
        vm = VariableMap()
        manager = Manager()
        manager.variable_map = vm
        vvar = VirtualVariable(7, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        const = Const(7, 0, 64)
        vvar_var = SimRegisterVariable(16, 8, ident="reg_1")
        const_var = SimConstantVariable(8, value=0, ident="const_0")
        vm.set_variable(vvar, vvar_var, 1)
        vm.set_variable(const, const_var, 2)

        copied_vvar = vvar.deep_copy(manager)

        self.assertNotEqual(copied_vvar.idx, vvar.idx)
        self.assertIs(vm.variable(copied_vvar), vvar_var)
        self.assertEqual(vm.variable_offset(copied_vvar), 1)
        self.assertTrue(vm.has_variable(copied_vvar))
        self.assertIsNone(vm.variable(copied_vvar.idx))
        self.assertEqual(vm.variable_offset(copied_vvar.idx), 0)
        self.assertFalse(vm.has_variable(copied_vvar.idx))
        self.assertIs(vm.variable(const), const_var)

    def test_side_effect_ret_expr_clear_is_occurrence_local(self):
        vm = VariableMap()
        manager = Manager()
        manager.variable_map = vm
        vvar = VirtualVariable(7, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        vvar_var = SimRegisterVariable(16, 8, ident="reg_1")
        vm.set_variable(vvar, vvar_var, 1)
        definition = SideEffectStatement(8, Const(9, 0, 64), ret_expr=vvar)

        copied_definition = definition.deep_copy(manager)
        copied_ret_expr = cast(VirtualVariable, copied_definition.ret_expr)
        self.assertIsInstance(copied_ret_expr, VirtualVariable)
        vm.set_variable(copied_ret_expr, None)

        self.assertIs(vm.variable(vvar), vvar_var)
        self.assertEqual(vm.variable_offset(vvar), 1)
        self.assertTrue(vm.has_variable(vvar))
        self.assertIsNone(vm.variable(copied_ret_expr))
        self.assertEqual(vm.variable_offset(copied_ret_expr), 0)
        self.assertFalse(vm.has_variable(copied_ret_expr))
        fresh_wrapper = VirtualVariable(99, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        self.assertIs(vm.variable(fresh_wrapper), vvar_var)
        self.assertEqual(vm.variable_offset(fresh_wrapper), 1)
        self.assertTrue(vm.has_variable(fresh_wrapper))

    def test_vvar_and_idx_atom_variable_namespaces(self):
        vm = VariableMap()
        vvar = VirtualVariable(7, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        duplicate_vvar = VirtualVariable(99, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        unmapped_vvar = VirtualVariable(7, 101, 64, VirtualVariableCategory.REGISTER, oident=24)
        const = Const(7, 0, 64)
        stmt = Assignment(
            8,
            VirtualVariable(9, 102, 64, VirtualVariableCategory.REGISTER, oident=32),
            Const(10, 1, 64),
        )
        vvar_var = SimRegisterVariable(16, 8, ident="reg_1")
        const_var = SimConstantVariable(8, value=0, ident="const_0")
        stmt_var = SimStackVariable(-0x10, 8, ident="stack_1")

        vm.set_variable(vvar, vvar_var, 1)
        vm.set_variable(const, const_var, 2)
        vm.set_variable(stmt, stmt_var, 3)

        # VirtualVariables use a stable varid default plus occurrence overrides. Duplicate wrappers with fresh idx
        # values must not consume a same-numbered idx mapping owned by another atom when their varid is unknown.
        self.assertIs(vm.variable(vvar), vvar_var)
        self.assertEqual(vm.variable_offset(vvar), 1)
        self.assertIs(vm.variable(duplicate_vvar), vvar_var)
        self.assertEqual(vm.variable_offset(duplicate_vvar), 1)
        self.assertIsNone(vm.variable(unmapped_vvar))
        self.assertEqual(vm.variable_offset(unmapped_vvar), 0)
        self.assertFalse(vm.has_variable(unmapped_vvar))

        # Non-VVar expressions, statements, and raw integer keys retain the existing idx-keyed behavior.
        self.assertIs(vm.variable(const), const_var)
        self.assertEqual(vm.variable_offset(const), 2)
        self.assertIs(vm.variable(7), const_var)
        self.assertIs(vm.variable(stmt), stmt_var)
        self.assertEqual(vm.variable_offset(stmt), 3)
        self.assertIs(vm.variable(8), stmt_var)

        # Clearing either namespace must leave the colliding entry in the other namespace intact.
        vm.set_variable(vvar, None)
        self.assertIsNone(vm.variable(vvar))
        self.assertEqual(vm.variable_offset(vvar), 0)
        self.assertFalse(vm.has_variable(vvar))
        self.assertIs(vm.variable(duplicate_vvar), vvar_var)
        self.assertEqual(vm.variable_offset(duplicate_vvar), 1)
        self.assertTrue(vm.has_variable(duplicate_vvar))
        self.assertIs(vm.variable(const), const_var)
        vm.set_variable(vvar, vvar_var, 1)
        self.assertIs(vm.variable(const), const_var)
        vm.set_variable(const, None)
        self.assertIs(vm.variable(vvar), vvar_var)
        self.assertIsNone(vm.variable(const))

        # The two namespaces are independent in the reverse insertion order as well.
        reverse_vm = VariableMap()
        reverse_vm.set_variable(const, const_var, 2)
        reverse_vm.set_variable(vvar, vvar_var, 1)
        self.assertIs(reverse_vm.variable(vvar), vvar_var)
        self.assertEqual(reverse_vm.variable_offset(vvar), 1)
        self.assertIs(reverse_vm.variable(const), const_var)
        self.assertEqual(reverse_vm.variable_offset(const), 2)

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
        vvar = VirtualVariable(6, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        duplicate_vvar = VirtualVariable(60, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        override_vvar = VirtualVariable(61, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        cleared_vvar = VirtualVariable(62, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        const = Const(6, 0, 64)
        v3 = SimRegisterVariable(16, 8, ident="reg_3")
        v4 = SimConstantVariable(8, value=0, ident="const_4")
        v5 = SimRegisterVariable(24, 8, ident="reg_5")
        vm.set_variable(vvar, v3, 3)
        vm.set_variable(const, v4, 4)
        vm.set_variable(override_vvar, v5, 5)
        vm.set_variable_offset(duplicate_vvar, 6)
        vm.set_variable(cleared_vvar, None)
        vm.set_variable_offset(cleared_vvar, 7)

        # ensure the result is JSON-serializable
        blob = json.dumps(vm.to_json())
        data = json.loads(blob)
        self.assertEqual(data["version"], 2)

        idents = {"reg_1": v1, "stack_2": v2, "reg_3": v3, "const_4": v4, "reg_5": v5}
        restored = VariableMap.from_json(data, idents.get)

        assert restored.variable(1) is v1
        assert restored.variable_offset(1) == 0
        assert restored.variable(2) is v2
        assert restored.variable_offset(2) == 8
        assert restored.custom_string(3) is True
        assert restored.reference_variable(4) is v2
        assert restored.reference_variable_offset(4) == 2
        self.assertIs(restored.variable(vvar), v3)
        self.assertEqual(restored.variable_offset(vvar), 3)
        self.assertIs(restored.variable(duplicate_vvar), v5)
        self.assertEqual(restored.variable_offset(duplicate_vvar), 6)
        self.assertIs(restored.variable(override_vvar), v5)
        self.assertEqual(restored.variable_offset(override_vvar), 5)
        self.assertIsNone(restored.variable(cleared_vvar))
        self.assertEqual(restored.variable_offset(cleared_vvar), 0)
        self.assertFalse(restored.has_variable(cleared_vvar))
        self.assertIs(restored.variable(const), v4)
        self.assertEqual(restored.variable_offset(const), 4)

        ref_vals = restored.reference_values(5)
        assert ref_vals is not None
        assert len(ref_vals) == 1
        (ty, val) = next(iter(ref_vals.items()))
        assert isinstance(ty, SimTypePointer)
        assert val == "hello"

    def test_legacy_json_discards_ambiguous_variable_entries(self):
        var = SimRegisterVariable(8, 8, ident="reg_1")
        data = {
            "variables": {"7": "reg_1"},
            "variable_offsets": {"7": 4},
            "custom_strings": {"9": True},
        }

        with self.assertLogs("angr.analyses.decompiler.variable_map", level="WARNING") as logs:
            restored = VariableMap.from_json(data, {"reg_1": var}.get)

        self.assertIn("discarding all variable and offset bindings", " ".join(logs.output).lower())
        self.assertIsNone(restored.variable(7))
        self.assertEqual(restored.variable_offset(7), 0)
        self.assertFalse(restored.has_variable(7))
        legacy_const = Const(7, 0, 64)
        self.assertIsNone(restored.variable(legacy_const))
        self.assertEqual(restored.variable_offset(legacy_const), 0)
        self.assertFalse(restored.has_variable(legacy_const))
        legacy_vvar = VirtualVariable(7, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        self.assertIsNone(restored.variable(legacy_vvar))
        self.assertEqual(restored.variable_offset(legacy_vvar), 0)
        self.assertFalse(restored.has_variable(legacy_vvar))
        self.assertTrue(restored.custom_string(9))

        with self.assertRaisesRegex(ValueError, "VariableMap serialization version"):
            VariableMap.from_json({"version": 999}, {"reg_1": var}.get)

    def test_json_unresolved_vvar_bindings_fail_closed_atomically(self):
        vm = VariableMap()
        vvar_a = VirtualVariable(6, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        vvar_b = VirtualVariable(7, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        fresh_vvar = VirtualVariable(8, 100, 64, VirtualVariableCategory.REGISTER, oident=8)
        var_a = SimRegisterVariable(8, 8, ident="reg_a")
        var_b = SimRegisterVariable(16, 8, ident="reg_b")
        vm.set_variable(vvar_a, var_a, 1)
        vm.set_variable(vvar_b, var_b, 2)
        data = json.loads(json.dumps(vm.to_json()))

        # The first occurrence cannot silently fall through to the resolved stable default for the same varid.
        with self.assertLogs("angr.analyses.decompiler.variable_map", level="WARNING"):
            restored = VariableMap.from_json(data, {"reg_b": var_b}.get)
        self.assertIsNone(restored.variable(vvar_a))
        self.assertEqual(restored.variable_offset(vvar_a), 0)
        self.assertFalse(restored.has_variable(vvar_a))
        self.assertIs(restored.variable(vvar_b), var_b)
        self.assertEqual(restored.variable_offset(vvar_b), 2)
        self.assertTrue(restored.has_variable(vvar_b))
        self.assertIs(restored.variable(fresh_vvar), var_b)
        self.assertEqual(restored.variable_offset(fresh_vvar), 2)

        # If the stable variable cannot be resolved, neither its stable offset nor an offset-only occurrence may
        # survive.
        stable_only_data = {
            "version": 2,
            "vvar_id_to_variable": {"101": "reg_a"},
            "vvar_id_to_variable_offset": {"101": 3},
            "vvar_occurrence_variable_offsets": [{"varid": 101, "idx": 10, "offset": 4}],
        }
        with self.assertLogs("angr.analyses.decompiler.variable_map", level="WARNING"):
            stable_unresolved = VariableMap.from_json(stable_only_data, {}.get)
        unresolved_vvar = VirtualVariable(11, 101, 64, VirtualVariableCategory.REGISTER, oident=8)
        offset_only_vvar = VirtualVariable(10, 101, 64, VirtualVariableCategory.REGISTER, oident=8)
        for candidate in (unresolved_vvar, offset_only_vvar):
            self.assertIsNone(stable_unresolved.variable(candidate))
            self.assertEqual(stable_unresolved.variable_offset(candidate), 0)
            self.assertFalse(stable_unresolved.has_variable(candidate))


if __name__ == "__main__":
    unittest.main()
