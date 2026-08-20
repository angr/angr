#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest
from typing import cast

import angr
from angr import ailment
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.decompiler.callsite_maker import CallSiteMaker
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCallsiteMaker(unittest.TestCase):
    @staticmethod
    def _register_destination(manager, project, offset, varid, use_vvar):
        if use_vvar:
            return ailment.Expr.VirtualVariable(
                manager.next_atom(),
                varid,
                project.arch.bits,
                ailment.Expr.VirtualVariableCategory.REGISTER,
                oident=offset,
            )
        return ailment.Expr.Register(manager.next_atom(), offset, project.arch.bits)

    @staticmethod
    def _assignment(manager, dst, src, ins_addr):
        return ailment.Stmt.Assignment(manager.next_atom(), dst, src, ins_addr=ins_addr)

    def _make_callsite(self, project, manager, block_addr, block_size, assignments):
        call = ailment.Expr.Call(
            manager.next_atom(),
            ailment.Expr.Const(manager.next_atom(), 0x2000, project.arch.bits),
            args=[],
            bits=project.arch.bits,
            ins_addr=block_addr + 2,
        )
        call_stmt = ailment.Stmt.SideEffectStatement(manager.next_atom(), call, ins_addr=block_addr + 2)
        block = ailment.Block(
            block_addr,
            original_size=block_size,
            statements=[*assignments, call_stmt],
        )

        callsite_maker = CallSiteMaker(project, block, ail_manager=manager)
        self.assertIsNotNone(callsite_maker.result_block)
        return callsite_maker, cast(ailment.Block, callsite_maker.result_block)

    def _assert_return_addr_assignment_removed(self, block):
        call_stmt = block.statements[-1]
        self.assertIsInstance(call_stmt, ailment.Stmt.SideEffectStatement)
        self.assertTrue(call_stmt.expr.tags.get("return_addr_assignment_removed", False))

    def test_synthetic_link_register_assignment(self):
        for arch_dir, binary, block_addr, block_size in (
            ("armel", "checkbyte", 0x1001, 4),
            ("aarch64", "test_loops", 0x1000, 4),
            ("ppc", "checkbyte", 0x1000, 4),
            ("mips", "checkbyte", 0x1000, 8),
            ("riscv64", "test_return_type_riscv64.elf", 0x1000, 4),
            ("s390x", "checkbyte", 0x1000, 6),
        ):
            project = angr.Project(
                os.path.join(test_location, arch_dir, binary),
                auto_load_libs=False,
            )
            self.assertFalse(project.arch.call_pushes_ret)
            lr_offset = project.arch.lr_offset
            if lr_offset is None and project.arch.name in {"MIPS32", "MIPS64"}:
                lr_offset = project.arch.registers["ra"][0]
            self.assertIsNotNone(lr_offset)

            for use_vvar in (False, True):
                with self.subTest(arch=project.arch.name, use_vvar=use_vvar):
                    self._check_synthetic_link_register_assignment(project, block_addr, block_size, lr_offset, use_vvar)

    def _check_synthetic_link_register_assignment(self, project, block_addr, block_size, lr_offset, use_vvar):
        manager = ailment.Manager(arch=project.arch)
        scratch_dst = self._register_destination(manager, project, lr_offset, 1, use_vvar)
        link_dst = self._register_destination(manager, project, lr_offset, 2, use_vvar)

        scratch_assignment = self._assignment(
            manager,
            scratch_dst,
            ailment.Expr.Const(manager.next_atom(), 1, project.arch.bits),
            block_addr,
        )
        link_assignment = self._assignment(
            manager,
            link_dst,
            ailment.Expr.Const(manager.next_atom(), block_addr + block_size, project.arch.bits),
            block_addr + 2,
        )
        callsite_maker, result_block = self._make_callsite(
            project,
            manager,
            block_addr,
            block_size,
            [scratch_assignment, link_assignment],
        )
        self.assertEqual(len(result_block.statements), 2)
        self.assertIs(result_block.statements[0], scratch_assignment)
        self.assertIsInstance(result_block.statements[1], ailment.Stmt.SideEffectStatement)
        self.assertEqual(callsite_maker.removed_vvar_ids, {2} if use_vvar else set())
        self._assert_return_addr_assignment_removed(result_block)

    def test_real_lifted_arm_link_register_assignment(self):
        project = angr.Project(
            os.path.join(test_location, "armel", "checkbyte"),
            auto_load_libs=False,
        )
        manager = ailment.Manager(arch=project.arch)
        block = project.factory.block(0x8370, size=8)
        self.assertEqual(block.vex.jumpkind, "Ijk_Call")
        ail_block = ailment.IRSBConverter.convert(block.vex, manager)

        link_assignment = ail_block.statements[-2]
        self.assertIsInstance(link_assignment, ailment.Stmt.Assignment)
        link_assignment = cast(ailment.Stmt.Assignment, link_assignment)
        self.assertIsInstance(link_assignment.dst, ailment.Expr.Register)
        link_dst = cast(ailment.Expr.Register, link_assignment.dst)
        self.assertEqual(link_dst.reg_offset, project.arch.lr_offset)
        self.assertIsInstance(link_assignment.src, ailment.Expr.Const)
        link_src = cast(ailment.Expr.Const, link_assignment.src)
        original_size = cast(int, ail_block.original_size)
        self.assertEqual(link_src.value, ail_block.addr + original_size)

        callsite_maker = CallSiteMaker(project, ail_block, ail_manager=manager)

        self.assertIsNotNone(callsite_maker.result_block)
        result_block = cast(ailment.Block, callsite_maker.result_block)
        self.assertEqual(len(result_block.statements), len(ail_block.statements) - 1)
        self.assertNotIn(link_assignment, result_block.statements)
        self._assert_return_addr_assignment_removed(result_block)

    def test_non_synthetic_link_register_assignment_survives(self):
        project = angr.Project(
            os.path.join(test_location, "armel", "checkbyte"),
            auto_load_libs=False,
        )
        block_addr = 0x1001
        block_size = 4
        lr_offset = project.arch.lr_offset
        self.assertIsNotNone(lr_offset)

        for use_vvar in (False, True):
            with self.subTest(use_vvar=use_vvar):
                manager = ailment.Manager(arch=project.arch)
                scratch_dst = self._register_destination(manager, project, lr_offset, 1, use_vvar)
                scratch_assignment = self._assignment(
                    manager,
                    scratch_dst,
                    ailment.Expr.Const(manager.next_atom(), 0x4242, project.arch.bits),
                    block_addr,
                )
                callsite_maker, result_block = self._make_callsite(
                    project,
                    manager,
                    block_addr,
                    block_size,
                    [scratch_assignment],
                )
                self.assertEqual(len(result_block.statements), 2)
                self.assertIs(result_block.statements[0], scratch_assignment)
                self.assertEqual(callsite_maker.removed_vvar_ids, set())

    def test_synthetic_link_register_assignment_removal_is_idempotent(self):
        project = angr.Project(
            os.path.join(test_location, "armel", "checkbyte"),
            auto_load_libs=False,
        )
        block_addr = 0x1001
        block_size = 4
        lr_offset = project.arch.lr_offset
        r0_offset = project.arch.registers["r0"][0]
        self.assertIsNotNone(lr_offset)

        for use_vvar in (False, True):
            with self.subTest(use_vvar=use_vvar):
                manager = ailment.Manager(arch=project.arch)
                scratch_dst = self._register_destination(manager, project, lr_offset, 1, use_vvar)
                scratch_use = self._register_destination(manager, project, lr_offset, 1, use_vvar)
                use_dst = self._register_destination(manager, project, r0_offset, 3, use_vvar)
                link_dst = self._register_destination(manager, project, lr_offset, 2, use_vvar)
                return_addr = ailment.Expr.Const(manager.next_atom(), block_addr + block_size, project.arch.bits)
                scratch_assignment = self._assignment(manager, scratch_dst, return_addr, block_addr)
                use_assignment = self._assignment(manager, use_dst, scratch_use, block_addr + 2)
                link_assignment = self._assignment(manager, link_dst, return_addr, block_addr + 2)
                first_callsite_maker, first_result = self._make_callsite(
                    project,
                    manager,
                    block_addr,
                    block_size,
                    [scratch_assignment, use_assignment, link_assignment],
                )
                self.assertEqual(len(first_result.statements), 3)
                self.assertEqual(first_callsite_maker.removed_vvar_ids, {2} if use_vvar else set())
                self._assert_return_addr_assignment_removed(first_result)

                second_callsite_maker = CallSiteMaker(project, first_result, ail_manager=manager)

                self.assertIsNotNone(second_callsite_maker.result_block)
                second_result = cast(ailment.Block, second_callsite_maker.result_block)
                self.assertEqual(len(second_result.statements), 3)
                self.assertIs(second_result.statements[0], scratch_assignment)
                self.assertIs(second_result.statements[1], use_assignment)
                self.assertEqual(second_callsite_maker.removed_vvar_ids, set())
                self._assert_return_addr_assignment_removed(second_result)

    def test_stack_return_address_assignment_removal_is_idempotent(self):
        project = angr.Project(
            os.path.join(test_location, "x86_64", "all"),
            auto_load_libs=False,
        )
        manager = ailment.Manager(arch=project.arch)
        block_addr = 0x1000
        block_size = 5
        return_addr = ailment.Expr.Const(manager.next_atom(), block_addr + block_size, project.arch.bits)
        scratch_store = ailment.Stmt.Store(
            manager.next_atom(),
            ailment.Expr.Const(manager.next_atom(), 0x3000, project.arch.bits),
            return_addr,
            project.arch.bytes,
            project.arch.memory_endness,
            ins_addr=block_addr,
        )
        link_store = ailment.Stmt.Store(
            manager.next_atom(),
            ailment.Expr.Const(manager.next_atom(), 0x4000, project.arch.bits),
            return_addr,
            project.arch.bytes,
            project.arch.memory_endness,
            ins_addr=block_addr,
        )

        _, first_result = self._make_callsite(
            project,
            manager,
            block_addr,
            block_size,
            [scratch_store, link_store],
        )
        self.assertEqual(len(first_result.statements), 2)
        self.assertIs(first_result.statements[0], scratch_store)
        self._assert_return_addr_assignment_removed(first_result)

        second_callsite_maker = CallSiteMaker(project, first_result, ail_manager=manager)

        self.assertIsNotNone(second_callsite_maker.result_block)
        second_result = cast(ailment.Block, second_callsite_maker.result_block)
        self.assertEqual(len(second_result.statements), 2)
        self.assertIs(second_result.statements[0], scratch_store)
        self.assertEqual(second_callsite_maker.removed_vvar_ids, set())
        self._assert_return_addr_assignment_removed(second_result)

    def test_s390x_noncanonical_link_preserves_lr_scratch(self):
        project = angr.Project(
            os.path.join(test_location, "s390x", "checkbyte"),
            auto_load_libs=False,
        )
        manager = ailment.Manager(arch=project.arch)
        block_addr = 0x1000
        block_size = 6
        lr_offset = project.arch.lr_offset
        other_link_offset = project.arch.registers["r0"][0]
        self.assertIsNotNone(lr_offset)

        scratch_dst = self._register_destination(manager, project, lr_offset, 1, False)
        link_dst = self._register_destination(manager, project, other_link_offset, 2, False)
        scratch_assignment = self._assignment(
            manager,
            scratch_dst,
            ailment.Expr.Const(manager.next_atom(), 0x4242, project.arch.bits),
            block_addr,
        )
        link_assignment = self._assignment(
            manager,
            link_dst,
            ailment.Expr.Const(manager.next_atom(), block_addr + block_size, project.arch.bits),
            block_addr + 2,
        )
        callsite_maker, result_block = self._make_callsite(
            project,
            manager,
            block_addr,
            block_size,
            [scratch_assignment, link_assignment],
        )
        self.assertEqual(len(result_block.statements), 3)
        self.assertIs(result_block.statements[0], scratch_assignment)
        self.assertIs(result_block.statements[1], link_assignment)
        self.assertEqual(callsite_maker.removed_vvar_ids, set())

    def test_callsite_maker(self):
        project = angr.Project(
            os.path.join(test_location, "x86_64", "all"),
            auto_load_libs=False,
        )

        manager = ailment.Manager(arch=project.arch)

        # Generate a CFG
        cfg = project.analyses.CFG()

        new_cc_found = True
        while new_cc_found:
            new_cc_found = False
            for func in cfg.kb.functions.values():
                if func.calling_convention is None:
                    # determine the calling convention of each function
                    project.analyses.VariableRecoveryFast(func)
                    cc_analysis = project.analyses.CallingConvention(func)
                    if cc_analysis.cc is not None:
                        func.calling_convention = cc_analysis.cc
                        func.prototype = cc_analysis.prototype
                        new_cc_found = True

        main_func = cfg.kb.functions["main"]

        for block in sorted(main_func.blocks, key=lambda x: x.addr):
            print(block.vex.pp())
            ail_block = ailment.IRSBConverter.convert(block.vex, manager)
            simp = BlockSimplifier(project, ail_block, manager, main_func.addr)

            csm = CallSiteMaker(project, simp.result_block, ail_manager=manager)
            if csm.result_block:
                ail_block = csm.result_block
                simp = BlockSimplifier(project, ail_block, manager, main_func.addr)

            print(simp.result_block)


if __name__ == "__main__":
    unittest.main()
