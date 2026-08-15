#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import ITE, Const, Phi, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.dephication.rewriting_engine import SimEngineDephiRewriting
from angr.analyses.decompiler.variable_map import VariableMap
from angr.rust.optimization_passes.redundant_block_remover import RedundantBlockRemover
from angr.sim_variable import SimConstantVariable, SimRegisterVariable
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDephicationRewriting(unittest.TestCase):
    """
    Dephication remaps every vvar feeding a phi onto the phi's destination and then drops the phi. If a remapped
    destination is not written back, the phi destination ends up with no definition and the phi sources with no uses,
    which passes that reason about vvar uses read as dead code.
    """

    @staticmethod
    def _engine(mapping, variable_map=None):
        # a project is only needed for the arch; no CFG or analyses required
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        return proj, SimEngineDephiRewriting(proj, mapping, variable_map=variable_map)

    def test_remapped_assignment_dst_transfers_occurrence_binding(self):
        vm = VariableMap()
        proj, engine = self._engine({11: 21, 12: 22}, vm)
        m = Manager(arch=proj.arch)
        src = VirtualVariable(7, 11, 64, VirtualVariableCategory.REGISTER)
        src_var = SimRegisterVariable(8, 8, ident="reg_src")
        dst_default = VirtualVariable(70, 21, 64, VirtualVariableCategory.REGISTER)
        dst_default_var = SimRegisterVariable(16, 8, ident="reg_dst_default")
        colliding_const = Const(src.idx, 1, 64)
        colliding_const_var = SimConstantVariable(8, value=1, ident="const_collision")
        vm.set_variable(src, src_var, 3)
        vm.set_variable(dst_default, dst_default_var, 4)
        vm.set_variable(colliding_const, colliding_const_var, 5)
        vm.set_custom_string(colliding_const)
        stmt = Assignment(m.next_atom(), src, Const(m.next_atom(), 0, 64))

        out = engine._handle_stmt_Assignment(stmt)

        assert isinstance(out, Assignment)
        rewritten_dst = out.dst
        assert isinstance(rewritten_dst, VirtualVariable)
        self.assertIs(vm.variable(rewritten_dst), src_var)
        self.assertEqual(vm.variable_offset(rewritten_dst), 3)
        fresh_wrapper = VirtualVariable(71, 21, 64, VirtualVariableCategory.REGISTER)
        self.assertIs(vm.variable(fresh_wrapper), dst_default_var)
        self.assertEqual(vm.variable_offset(fresh_wrapper), 4)
        self.assertIs(vm.variable(colliding_const), colliding_const_var)
        self.assertEqual(vm.variable_offset(colliding_const), 5)
        self.assertTrue(vm.custom_string(colliding_const))

        tombstoned_src = VirtualVariable(17, 12, 64, VirtualVariableCategory.REGISTER)
        tombstoned_dst_default = VirtualVariable(72, 22, 64, VirtualVariableCategory.REGISTER)
        tombstoned_dst_default_var = SimRegisterVariable(24, 8, ident="reg_tombstone_default")
        vm.set_variable(tombstoned_src, src_var, 6)
        vm.set_variable(tombstoned_src, None)
        vm.set_variable(tombstoned_dst_default, tombstoned_dst_default_var, 7)
        tombstoned_stmt = Assignment(m.next_atom(), tombstoned_src, Const(m.next_atom(), 0, 64))

        tombstoned_out = engine._handle_stmt_Assignment(tombstoned_stmt)

        assert isinstance(tombstoned_out, Assignment)
        rewritten_tombstone = tombstoned_out.dst
        assert isinstance(rewritten_tombstone, VirtualVariable)
        self.assertIsNone(vm.variable(rewritten_tombstone))
        self.assertEqual(vm.variable_offset(rewritten_tombstone), 0)
        self.assertFalse(vm.has_variable(rewritten_tombstone))
        fresh_tombstone_wrapper = VirtualVariable(73, 22, 64, VirtualVariableCategory.REGISTER)
        self.assertIs(vm.variable(fresh_tombstone_wrapper), tombstoned_dst_default_var)

    def test_remapped_vvar_expr_transfers_occurrence_binding(self):
        vm = VariableMap()
        _, engine = self._engine({31: 41, 32: 42}, vm)
        src = VirtualVariable(27, 31, 64, VirtualVariableCategory.REGISTER)
        src_var = SimRegisterVariable(8, 8, ident="reg_src")
        dst_default = VirtualVariable(80, 41, 64, VirtualVariableCategory.REGISTER)
        dst_default_var = SimRegisterVariable(16, 8, ident="reg_dst_default")
        colliding_const = Const(src.idx, 1, 64)
        colliding_const_var = SimConstantVariable(8, value=1, ident="const_collision")
        vm.set_variable(src, src_var, 3)
        vm.set_variable(dst_default, dst_default_var, 4)
        vm.set_variable(colliding_const, colliding_const_var, 5)
        vm.set_custom_string(colliding_const)

        rewritten = engine._handle_expr_VirtualVariable(src)

        assert isinstance(rewritten, VirtualVariable)
        self.assertIs(vm.variable(rewritten), src_var)
        self.assertEqual(vm.variable_offset(rewritten), 3)
        fresh_wrapper = VirtualVariable(81, 41, 64, VirtualVariableCategory.REGISTER)
        self.assertIs(vm.variable(fresh_wrapper), dst_default_var)
        self.assertEqual(vm.variable_offset(fresh_wrapper), 4)
        self.assertIs(vm.variable(colliding_const), colliding_const_var)
        self.assertEqual(vm.variable_offset(colliding_const), 5)
        self.assertTrue(vm.custom_string(colliding_const))

        tombstoned_src = VirtualVariable(37, 32, 64, VirtualVariableCategory.REGISTER)
        tombstoned_dst_default = VirtualVariable(82, 42, 64, VirtualVariableCategory.REGISTER)
        tombstoned_dst_default_var = SimRegisterVariable(24, 8, ident="reg_tombstone_default")
        vm.set_variable(tombstoned_src, src_var, 6)
        vm.set_variable(tombstoned_src, None)
        vm.set_variable(tombstoned_dst_default, tombstoned_dst_default_var, 7)

        rewritten_tombstone = engine._handle_expr_VirtualVariable(tombstoned_src)

        assert isinstance(rewritten_tombstone, VirtualVariable)
        self.assertIsNone(vm.variable(rewritten_tombstone))
        self.assertEqual(vm.variable_offset(rewritten_tombstone), 0)
        self.assertFalse(vm.has_variable(rewritten_tombstone))
        fresh_tombstone_wrapper = VirtualVariable(83, 42, 64, VirtualVariableCategory.REGISTER)
        self.assertIs(vm.variable(fresh_tombstone_wrapper), tombstoned_dst_default_var)

    def test_remapped_dst_survives_non_vvar_src(self):
        _, engine = self._engine({2759: 1330})
        m = Manager()
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 2759, 64, VirtualVariableCategory.REGISTER),
            # a source that is not a bare vvar; this is what used to discard the remapped destination
            UnaryOp(
                m.next_atom(),
                "Reference",
                VirtualVariable(m.next_atom(), 4575, 128, VirtualVariableCategory.STACK),
                bits=64,
            ),
            ins_addr=0x400100,
        )

        out = engine._handle_stmt_Assignment(stmt)
        assert isinstance(out, Assignment)
        assert out.dst.varid == 1330

    def test_remapped_dst_survives_const_src(self):
        _, engine = self._engine({7: 3})
        m = Manager()
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 7, 64, VirtualVariableCategory.REGISTER),
            Const(m.next_atom(), 0x1234, 64),
            ins_addr=0x400100,
        )

        out = engine._handle_stmt_Assignment(stmt)
        assert isinstance(out, Assignment)
        assert out.dst.varid == 3

    def test_self_assignment_is_still_dropped(self):
        # the reason the return used to sit behind the both-sides-are-vvars guard: once both sides map onto the same
        # variable the statement is a no-op and has to go away
        _, engine = self._engine({11: 3, 12: 3})
        m = Manager()
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 11, 64, VirtualVariableCategory.REGISTER),
            VirtualVariable(m.next_atom(), 12, 64, VirtualVariableCategory.REGISTER),
            ins_addr=0x400100,
        )

        assert engine._handle_stmt_Assignment(stmt) == ()

    def test_unmapped_assignment_is_left_alone(self):
        _, engine = self._engine({2759: 1330})
        m = Manager()
        stmt = Assignment(
            m.next_atom(),
            VirtualVariable(m.next_atom(), 99, 64, VirtualVariableCategory.REGISTER),
            Const(m.next_atom(), 1, 64),
            ins_addr=0x400100,
        )

        # None means "unchanged" to the caller, which then keeps the original statement
        assert engine._handle_stmt_Assignment(stmt) is None

    def test_ite_branches_are_not_swapped(self):
        # ailment's ITE takes (idx, cond, iftrue, iffalse): a rebuild that feeds the branches in
        # the wrong order silently inverts the ternary, e.g. `c ? x : -1` comes out as `c ? -1 : x`
        _, engine = self._engine({5: 6})
        m = Manager()
        cond = VirtualVariable(m.next_atom(), 5, 1, VirtualVariableCategory.REGISTER)
        iffalse = Const(m.next_atom(), 0xFFFFFFFF, 32)
        iftrue = Const(m.next_atom(), 0x11, 32)
        expr = ITE(m.next_atom(), cond, iftrue, iffalse, ins_addr=0x400100)

        # only the condition is remapped, so the rebuild is driven purely by the new condition
        out = engine._handle_expr_ITE(expr)
        assert isinstance(out, ITE)
        assert out.cond.varid == 6
        assert out.iftrue.value == 0x11
        assert out.iffalse.value == 0xFFFFFFFF
    def test_redundant_block_remover_dephication_preserves_occurrence_binding(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        func = proj.kb.functions.function(addr=proj.entry, create=True)
        assert func is not None
        vm = VariableMap()
        manager = Manager(arch=proj.arch)
        manager.variable_map = vm

        source_for_phi = VirtualVariable(1, 100, 64, VirtualVariableCategory.REGISTER)
        source_use = VirtualVariable(2, 100, 64, VirtualVariableCategory.REGISTER)
        phi_dst = VirtualVariable(3, 200, 64, VirtualVariableCategory.REGISTER)
        block = Block(
            func.addr,
            4,
            statements=[
                Assignment(4, phi_dst, Phi(5, 64, [((func.addr, None), source_for_phi)])),
                Return(6, [source_use]),
            ],
            idx=None,
        )
        graph = networkx.DiGraph()
        graph.add_node(block)

        source_default = VirtualVariable(10, 100, 64, VirtualVariableCategory.REGISTER)
        destination_default = VirtualVariable(11, 200, 64, VirtualVariableCategory.REGISTER)
        source_override_var = SimRegisterVariable(8, 8, ident="reg_source_override")
        source_default_var = SimRegisterVariable(16, 8, ident="reg_source_default")
        destination_default_var = SimRegisterVariable(24, 8, ident="reg_destination_default")
        vm.set_variable(source_use, source_override_var, 3)
        vm.set_variable(source_default, source_default_var, 4)
        vm.set_variable(destination_default, destination_default_var, 5)

        remover = RedundantBlockRemover(func, manager, graph=graph)
        remover._remove_redundant_blocks(dephicate=True)

        rewritten_block = next(iter(remover._graph.nodes))
        self.assertEqual(len(rewritten_block.statements), 1)
        rewritten_return = rewritten_block.statements[0]
        self.assertIsInstance(rewritten_return, Return)
        rewritten_use = rewritten_return.ret_exprs[0]
        self.assertIsInstance(rewritten_use, VirtualVariable)
        self.assertEqual(rewritten_use.varid, phi_dst.varid)
        self.assertIs(vm.variable(rewritten_use), source_override_var)
        self.assertEqual(vm.variable_offset(rewritten_use), 3)
        self.assertIs(vm.variable(destination_default), destination_default_var)
        self.assertEqual(vm.variable_offset(destination_default), 5)

    def test_bbbq_rust_flavor_keeps_string_constants(self):
        """
        sub_410920 sets up a &str in a block whose only outward effect flows through a phi. With the remapped
        destination dropped, RedundantBlockRemover deleted the block and the string with it.
        """
        bin_path = os.path.join(test_location, "x86_64", "bbbq")
        # the window has to reach past the function: with a tighter scope the callee prototypes differ enough that the
        # block holding this string survives even with the bug, and the test stops testing anything
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x410920, window=0x4000, expand_call_tree=False, run_ccc=False
        )
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        dec = proj.analyses.Decompiler(0x410920, cfg=cfg.model, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "seed_hex is not valid hex" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
