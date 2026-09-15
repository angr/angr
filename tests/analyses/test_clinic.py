#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock

import capstone
import networkx
from archinfo import ArchARMEL, ArchPcode

import angr
import angr.analyses.decompiler
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.stack_pointer_tracker import TOP, OffsetVal
from angr.codenode import BlockNode
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestClinic(unittest.TestCase):
    @staticmethod
    def _arm_reg_operand(reg, *, shift=capstone.arm.ARM_SFT_INVALID):
        return SimpleNamespace(
            type=capstone.arm.ARM_OP_REG,
            reg=reg,
            shift=SimpleNamespace(type=shift),
        )

    @staticmethod
    def _arm_imm_operand(value):
        return SimpleNamespace(type=capstone.arm.ARM_OP_IMM, imm=value)

    @classmethod
    def _arm_insn(
        cls,
        insn_id,
        operands,
        writes,
        *,
        reads=(),
        cc=capstone.arm.ARM_CC_AL,
        size=2,
        update_flags=False,
        writeback=False,
    ):
        reads = tuple(reads)
        writes = tuple(writes)
        return SimpleNamespace(
            id=insn_id,
            cc=cc,
            operands=operands,
            size=size,
            update_flags=update_flags,
            writeback=writeback,
            regs_access=lambda: (reads, writes),
        )

    @classmethod
    def _arm_copy(cls, dst, src, *, cc=capstone.arm.ARM_CC_AL):
        return cls._arm_insn(
            capstone.arm.ARM_INS_MOV,
            [cls._arm_reg_operand(dst), cls._arm_reg_operand(src)],
            [dst],
            reads=[src],
            cc=cc,
        )

    @classmethod
    def _arm_affine_copy(cls, dst, src, *, cc=capstone.arm.ARM_CC_AL):
        return cls._arm_insn(
            capstone.arm.ARM_INS_ADD,
            [cls._arm_reg_operand(dst), cls._arm_reg_operand(src), cls._arm_imm_operand(0)],
            [dst],
            reads=[src],
            cc=cc,
        )

    @classmethod
    def _arm_adjust(
        cls,
        dst,
        value,
        *,
        src=None,
        insn_id=capstone.arm.ARM_INS_ADD,
        cc=capstone.arm.ARM_CC_AL,
        shift=capstone.arm.ARM_SFT_INVALID,
        writes=None,
        update_flags=True,
        writeback=False,
    ):
        if src is None:
            operands = [cls._arm_reg_operand(dst, shift=shift), cls._arm_imm_operand(value)]
            reads = [dst]
        else:
            operands = [
                cls._arm_reg_operand(dst),
                cls._arm_reg_operand(src, shift=shift),
                cls._arm_imm_operand(value),
            ]
            reads = [src]
        return cls._arm_insn(
            insn_id,
            operands,
            [dst] if writes is None else writes,
            reads=reads,
            cc=cc,
            update_flags=update_flags,
            writeback=writeback,
        )

    @staticmethod
    def _arm_block(
        node,
        instructions,
        *,
        vex_instruction_count=None,
        vex_instruction_addresses=None,
        vex_size=None,
        vex_jumpkind="Ijk_Boring",
    ):
        for offset, insn in enumerate(instructions):
            insn.address = node.addr + offset * insn.size
        instruction_count = len(instructions) if vex_instruction_count is None else vex_instruction_count
        vex = SimpleNamespace(
            instructions=instruction_count,
            instruction_addresses=(
                tuple(insn.address for insn in instructions)
                if vex_instruction_addresses is None
                else vex_instruction_addresses
            ),
            size=node.size if vex_size is None else vex_size,
            jumpkind=vex_jumpkind,
        )
        return SimpleNamespace(capstone=SimpleNamespace(insns=instructions), vex=vex)

    @staticmethod
    def _arm_clinic(graph, blocks):
        arch = ArchARMEL()
        factory = SimpleNamespace(block=mock.Mock(side_effect=lambda addr, **_: blocks[addr]))
        clinic = object.__new__(Clinic)
        clinic.project = cast(angr.Project, SimpleNamespace(arch=arch, factory=factory))
        entry = next(node for node in graph if graph.in_degree(node) == 0)
        clinic.entry_node_addr = (entry.addr, None)
        return clinic

    @classmethod
    def _single_block_saved_sp(cls, middle=(), post_restore=(), *, save=None, restore=None):
        save = save or cls._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP)
        restore = restore or cls._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)
        instructions = [save, *middle, restore, *post_restore]
        node = BlockNode(0x1001, sum(insn.size for insn in instructions), thumb=True)
        graph = networkx.DiGraph()
        graph.add_node(node)
        return graph, {node.addr: cls._arm_block(node, instructions)}

    def test_smoketest(self):
        binary_path = os.path.join(test_location, "x86_64", "all")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=True)

        cfg = proj.analyses.CFG(normalize=True)
        main_func = cfg.kb.functions["main"]

        proj.analyses.Clinic(main_func)

    def test_arm_saved_sp_without_capstone_fails_closed(self):
        arch = object.__new__(ArchPcode)
        arch.name = "ARM:LE:32:Cortex"
        assert not arch.capstone_support

        block = BlockNode(0x1001, 2, thumb=True)
        graph = networkx.DiGraph()
        graph.add_node(block)

        factory = SimpleNamespace(block=mock.Mock(side_effect=AssertionError("Capstone must not be used")))
        clinic = object.__new__(Clinic)
        clinic.project = cast(angr.Project, SimpleNamespace(arch=arch, factory=factory))
        clinic.entry_node_addr = (block.addr, None)

        assert clinic._find_regs_saving_sp(graph) == set()  # pylint: disable=protected-access
        factory.block.assert_not_called()

    def test_arm_saved_sp_in_it_block_fails_closed(self):
        arch = ArchARMEL()

        instructions = [
            self._arm_insn(capstone.arm.ARM_INS_IT, [], []),
            self._arm_affine_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP),
            self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7),
        ]

        block = BlockNode(0x1001, 6, thumb=True)
        graph = networkx.DiGraph()
        graph.add_node(block)
        factory = SimpleNamespace(
            block=mock.Mock(return_value=SimpleNamespace(capstone=SimpleNamespace(insns=instructions)))
        )
        clinic = object.__new__(Clinic)
        clinic.project = cast(angr.Project, SimpleNamespace(arch=arch, factory=factory))
        clinic.entry_node_addr = (block.addr, None)

        assert clinic._find_regs_saving_sp(graph) == set()  # pylint: disable=protected-access
        factory.block.assert_called_once_with(block.addr, size=block.size, thumb=True, cross_insn_opt=False)

    def test_arm_saved_sp_conditional_save_fails_closed(self):
        save = self._arm_affine_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP, cc=capstone.arm.ARM_CC_EQ)
        graph, blocks = self._single_block_saved_sp(save=save)
        clinic = self._arm_clinic(graph, blocks)

        self.assertEqual(clinic._find_regs_saving_sp(graph), set())  # pylint: disable=protected-access

    def test_arm_saved_sp_invalid_condition_fails_closed(self):
        save = self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP, cc=capstone.arm.ARM_CC_INVALID)
        graph, blocks = self._single_block_saved_sp(save=save)
        clinic = self._arm_clinic(graph, blocks)

        self.assertEqual(clinic._find_regs_saving_sp(graph), set())  # pylint: disable=protected-access

    def test_arm_saved_sp_clobbers_fail_closed(self):
        clobbers = {
            "explicit": self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_R11),
            "load": self._arm_insn(
                capstone.arm.ARM_INS_LDR,
                [self._arm_reg_operand(capstone.arm.ARM_REG_R7), self._arm_reg_operand(capstone.arm.ARM_REG_R0)],
                [capstone.arm.ARM_REG_R7],
                reads=[capstone.arm.ARM_REG_R0],
            ),
            "implicit": self._arm_insn(
                capstone.arm.ARM_INS_POP,
                [self._arm_reg_operand(capstone.arm.ARM_REG_R7)],
                [capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP],
                reads=[capstone.arm.ARM_REG_SP],
            ),
            "writeback": self._arm_insn(
                capstone.arm.ARM_INS_LDR,
                [self._arm_reg_operand(capstone.arm.ARM_REG_R0), self._arm_reg_operand(capstone.arm.ARM_REG_R7)],
                [capstone.arm.ARM_REG_R0, capstone.arm.ARM_REG_R7],
                reads=[capstone.arm.ARM_REG_R7],
            ),
        }

        for clobber_kind, clobber in clobbers.items():
            with self.subTest(clobber_kind=clobber_kind):
                graph, blocks = self._single_block_saved_sp(middle=[clobber])
                clinic = self._arm_clinic(graph, blocks)
                self.assertEqual(
                    clinic._find_regs_saving_sp(graph),  # pylint: disable=protected-access
                    set(),
                )

    def test_arm_saved_sp_branched_clobber_fails_closed(self):
        entry_insns = [self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP)]
        clobber_insns = [self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_R11)]
        restore_insns = [self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)]
        entry = BlockNode(0x1001, 2, thumb=True)
        clobber = BlockNode(0x1101, 2, thumb=True)
        left_endpoint = BlockNode(0x1201, 2, thumb=True)
        right_endpoint = BlockNode(0x1301, 2, thumb=True)
        graph = networkx.DiGraph([(entry, clobber), (clobber, left_endpoint), (entry, right_endpoint)])
        blocks = {
            entry.addr: self._arm_block(entry, entry_insns),
            clobber.addr: self._arm_block(clobber, clobber_insns),
            left_endpoint.addr: self._arm_block(left_endpoint, restore_insns),
            right_endpoint.addr: self._arm_block(
                right_endpoint, [self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)]
            ),
        }
        clinic = self._arm_clinic(graph, blocks)

        self.assertEqual(clinic._find_regs_saving_sp(graph), set())  # pylint: disable=protected-access

    def test_arm_saved_sp_restore_topology_fails_closed(self):
        def save():
            return self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP)

        def restore():
            return self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)

        entry = BlockNode(0x1001, 2, thumb=True)
        left_endpoint = BlockNode(0x1101, 2, thumb=True)
        right_endpoint = BlockNode(0x1201, 2, thumb=True)
        missing_graph = networkx.DiGraph([(entry, left_endpoint), (entry, right_endpoint)])
        missing_blocks = {
            entry.addr: self._arm_block(entry, [save()]),
            left_endpoint.addr: self._arm_block(left_endpoint, [restore()]),
            right_endpoint.addr: self._arm_block(right_endpoint, [self._arm_insn(capstone.arm.ARM_INS_NOP, [], [])]),
        }

        duplicate_node = BlockNode(0x2001, 6, thumb=True)
        duplicate_graph = networkx.DiGraph()
        duplicate_graph.add_node(duplicate_node)
        duplicate_blocks = {duplicate_node.addr: self._arm_block(duplicate_node, [save(), restore(), restore()])}

        non_endpoint_entry = BlockNode(0x3001, 2, thumb=True)
        non_endpoint_restore = BlockNode(0x3101, 2, thumb=True)
        non_endpoint_endpoint = BlockNode(0x3201, 2, thumb=True)
        non_endpoint_graph = networkx.DiGraph(
            [(non_endpoint_entry, non_endpoint_restore), (non_endpoint_restore, non_endpoint_endpoint)]
        )
        non_endpoint_blocks = {
            non_endpoint_entry.addr: self._arm_block(non_endpoint_entry, [save()]),
            non_endpoint_restore.addr: self._arm_block(non_endpoint_restore, [restore()]),
            non_endpoint_endpoint.addr: self._arm_block(non_endpoint_endpoint, [restore()]),
        }

        reversed_node = BlockNode(0x4001, 4, thumb=True)
        reversed_graph = networkx.DiGraph()
        reversed_graph.add_node(reversed_node)
        reversed_blocks = {reversed_node.addr: self._arm_block(reversed_node, [restore(), save()])}

        cases = {
            "missing_endpoint_restore": (missing_graph, missing_blocks),
            "duplicate_endpoint_restore": (duplicate_graph, duplicate_blocks),
            "non_endpoint_restore": (non_endpoint_graph, non_endpoint_blocks),
            "restore_before_save": (reversed_graph, reversed_blocks),
        }
        for topology_kind, (graph, blocks) in cases.items():
            with self.subTest(topology_kind=topology_kind):
                clinic = self._arm_clinic(graph, blocks)
                self.assertEqual(
                    clinic._find_regs_saving_sp(graph),  # pylint: disable=protected-access
                    set(),
                )

    def test_arm_saved_sp_real_endpoint_affine_adjustment_is_allowed(self):
        adjustment = self._arm_adjust(capstone.arm.ARM_REG_R7, 24)
        graph, blocks = self._single_block_saved_sp(middle=[adjustment])
        clinic = self._arm_clinic(graph, blocks)
        r7_offset = clinic.project.arch.registers["r7"][0]

        self.assertEqual(
            clinic._find_regs_saving_sp(graph),  # pylint: disable=protected-access
            {r7_offset},
        )

    def test_arm_saved_sp_endpoint_affine_adjustments_fail_closed(self):
        adjustments = {
            "conditional": self._arm_adjust(capstone.arm.ARM_REG_R7, 24, cc=capstone.arm.ARM_CC_EQ),
            "other_source": self._arm_adjust(capstone.arm.ARM_REG_R7, 24, src=capstone.arm.ARM_REG_R6),
            "three_operand_add": self._arm_adjust(capstone.arm.ARM_REG_R7, 24, src=capstone.arm.ARM_REG_R7),
            "two_operand_sub": self._arm_adjust(capstone.arm.ARM_REG_R7, 24, insn_id=capstone.arm.ARM_INS_SUB),
            "three_operand_sub": self._arm_adjust(
                capstone.arm.ARM_REG_R7,
                24,
                src=capstone.arm.ARM_REG_R7,
                insn_id=capstone.arm.ARM_INS_SUB,
            ),
            "register_rhs": self._arm_insn(
                capstone.arm.ARM_INS_ADD,
                [
                    self._arm_reg_operand(capstone.arm.ARM_REG_R7),
                    self._arm_reg_operand(capstone.arm.ARM_REG_R7),
                    self._arm_reg_operand(capstone.arm.ARM_REG_R0),
                ],
                [capstone.arm.ARM_REG_R7],
                reads=[capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_R0],
                update_flags=True,
            ),
            "shifted_source": self._arm_adjust(
                capstone.arm.ARM_REG_R7,
                24,
                src=capstone.arm.ARM_REG_R7,
                shift=capstone.arm.ARM_SFT_LSL,
            ),
            "implicit_write": self._arm_adjust(
                capstone.arm.ARM_REG_R0,
                24,
                writes=[capstone.arm.ARM_REG_R0, capstone.arm.ARM_REG_R7],
            ),
            "writeback": self._arm_adjust(capstone.arm.ARM_REG_R7, 24, writeback=True),
            "no_flags_update": self._arm_adjust(capstone.arm.ARM_REG_R7, 24, update_flags=False),
            "unknown_alias": self._arm_adjust(capstone.arm.ARM_REG_R7, 24, insn_id=capstone.arm.ARM_INS_ADC),
        }

        for adjustment_kind, adjustment in adjustments.items():
            with self.subTest(adjustment_kind=adjustment_kind):
                graph, blocks = self._single_block_saved_sp(middle=[adjustment])
                clinic = self._arm_clinic(graph, blocks)
                self.assertEqual(
                    clinic._find_regs_saving_sp(graph),  # pylint: disable=protected-access
                    set(),
                )

    def test_arm_saved_sp_non_endpoint_affine_adjustments_fail_closed(self):
        for adjusted_paths in ("one", "all"):
            with self.subTest(adjusted_paths=adjusted_paths):
                entry = BlockNode(0x1001, 2, thumb=True)
                left = BlockNode(0x1101, 2, thumb=True)
                right = BlockNode(0x1201, 2, thumb=True)
                left_endpoint = BlockNode(0x1301, 2, thumb=True)
                right_endpoint = BlockNode(0x1401, 2, thumb=True)
                graph = networkx.DiGraph(
                    [
                        (entry, left),
                        (entry, right),
                        (left, left_endpoint),
                        (right, right_endpoint),
                    ]
                )
                blocks = {
                    entry.addr: self._arm_block(
                        entry, [self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP)]
                    ),
                    left.addr: self._arm_block(left, [self._arm_adjust(capstone.arm.ARM_REG_R7, 24)]),
                    right.addr: self._arm_block(
                        right,
                        [
                            self._arm_adjust(capstone.arm.ARM_REG_R7, 24)
                            if adjusted_paths == "all"
                            else self._arm_insn(capstone.arm.ARM_INS_NOP, [], [])
                        ],
                    ),
                    left_endpoint.addr: self._arm_block(
                        left_endpoint,
                        [self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)],
                    ),
                    right_endpoint.addr: self._arm_block(
                        right_endpoint,
                        [self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)],
                    ),
                }
                clinic = self._arm_clinic(graph, blocks)

                self.assertEqual(
                    clinic._find_regs_saving_sp(graph),  # pylint: disable=protected-access
                    set(),
                )

    def test_arm_saved_sp_loop_affine_adjustment_fails_closed(self):
        entry = BlockNode(0x1001, 2, thumb=True)
        loop = BlockNode(0x1101, 2, thumb=True)
        endpoint = BlockNode(0x1201, 2, thumb=True)
        graph = networkx.DiGraph([(entry, loop), (loop, loop), (loop, endpoint)])
        blocks = {
            entry.addr: self._arm_block(entry, [self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP)]),
            loop.addr: self._arm_block(loop, [self._arm_adjust(capstone.arm.ARM_REG_R7, 24)]),
            endpoint.addr: self._arm_block(
                endpoint, [self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)]
            ),
        }
        clinic = self._arm_clinic(graph, blocks)

        self.assertEqual(clinic._find_regs_saving_sp(graph), set())  # pylint: disable=protected-access

    def test_arm_saved_sp_multiple_endpoint_affine_adjustments_are_allowed(self):
        entry = BlockNode(0x1001, 2, thumb=True)
        left_endpoint = BlockNode(0x1101, 4, thumb=True)
        right_endpoint = BlockNode(0x1201, 4, thumb=True)
        graph = networkx.DiGraph([(entry, left_endpoint), (entry, right_endpoint)])
        blocks = {
            entry.addr: self._arm_block(entry, [self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP)]),
            left_endpoint.addr: self._arm_block(
                left_endpoint,
                [
                    self._arm_adjust(capstone.arm.ARM_REG_R7, 24),
                    self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7),
                ],
            ),
            right_endpoint.addr: self._arm_block(
                right_endpoint,
                [
                    self._arm_adjust(
                        capstone.arm.ARM_REG_R7,
                        24,
                    ),
                    self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7),
                ],
            ),
        }
        clinic = self._arm_clinic(graph, blocks)
        r7_offset = clinic.project.arch.registers["r7"][0]

        self.assertEqual(
            clinic._find_regs_saving_sp(graph),  # pylint: disable=protected-access
            {r7_offset},
        )

    def test_arm_saved_sp_write_after_restore_is_allowed(self):
        pop_r7 = self._arm_insn(
            capstone.arm.ARM_INS_POP,
            [self._arm_reg_operand(capstone.arm.ARM_REG_R7)],
            [capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP],
            reads=[capstone.arm.ARM_REG_SP],
        )
        graph, blocks = self._single_block_saved_sp(post_restore=[pop_r7])
        clinic = self._arm_clinic(graph, blocks)
        r7_offset = clinic.project.arch.registers["r7"][0]

        self.assertEqual(clinic._find_regs_saving_sp(graph), {r7_offset})  # pylint: disable=protected-access

    def test_arm_saved_sp_unknown_register_access_fails_closed(self):
        unknown = self._arm_insn(capstone.arm.ARM_INS_NOP, [], [])

        def unavailable_access():
            raise capstone.CsError(capstone.CS_ERR_DETAIL)

        unknown.regs_access = unavailable_access
        graph, blocks = self._single_block_saved_sp(middle=[unknown])
        clinic = self._arm_clinic(graph, blocks)

        self.assertEqual(clinic._find_regs_saving_sp(graph), set())  # pylint: disable=protected-access

    def test_arm_saved_sp_vex_mismatches_fail_closed(self):
        for mismatch_kind in ("instruction_count", "instruction_addresses", "size", "no_decode"):
            with self.subTest(mismatch_kind=mismatch_kind):
                graph, blocks = self._single_block_saved_sp()
                node = next(iter(graph))
                instructions = blocks[node.addr].capstone.insns
                block_options: dict[str, Any] = {}
                if mismatch_kind == "instruction_count":
                    block_options["vex_instruction_count"] = len(instructions) - 1
                elif mismatch_kind == "instruction_addresses":
                    addresses = tuple(insn.address for insn in instructions)
                    block_options["vex_instruction_addresses"] = (addresses[0] + 2, *addresses[1:])
                elif mismatch_kind == "size":
                    block_options["vex_size"] = node.size - 2
                else:
                    block_options["vex_jumpkind"] = "Ijk_NoDecode"
                blocks[node.addr] = self._arm_block(node, instructions, **block_options)
                clinic = self._arm_clinic(graph, blocks)

                self.assertEqual(
                    clinic._find_regs_saving_sp(graph),  # pylint: disable=protected-access
                    set(),
                )

    def test_arm_saved_sp_candidate_initial_value_is_top(self):
        save = self._arm_copy(capstone.arm.ARM_REG_R11, capstone.arm.ARM_REG_SP)
        restore = self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R11)
        graph, blocks = self._single_block_saved_sp(save=save, restore=restore)
        clinic = self._arm_clinic(graph, blocks)
        cast(Any, clinic).function = SimpleNamespace(graph=graph, normalized=True)
        clinic._func_graph = graph  # pylint: disable=protected-access
        clinic._sp_shift = 0  # pylint: disable=protected-access
        clinic._fail_fast = False  # pylint: disable=protected-access
        clinic._sp_tracker_track_memory = False  # pylint: disable=protected-access
        stack_pointer_tracker = SimpleNamespace(inconsistent_for=mock.Mock(return_value=False))
        stack_pointer_tracker_analysis = mock.Mock(return_value=stack_pointer_tracker)
        cast(Any, clinic.project).analyses = SimpleNamespace(StackPointerTracker=stack_pointer_tracker_analysis)

        self.assertIs(clinic._track_stack_pointers(), stack_pointer_tracker)  # pylint: disable=protected-access

        _, tracked_regs = stack_pointer_tracker_analysis.call_args.args
        initial_reg_values = stack_pointer_tracker_analysis.call_args.kwargs["initial_reg_values"]
        r11_offset = clinic.project.arch.registers["r11"][0]
        self.assertEqual(r11_offset, clinic.project.arch.bp_offset)
        self.assertIn(r11_offset, tracked_regs)
        self.assertIs(initial_reg_values[r11_offset], TOP)
        self.assertIsInstance(initial_reg_values[clinic.project.arch.sp_offset], OffsetVal)

    def test_arm_saved_sp_unnormalized_function_fails_closed(self):
        graph, blocks = self._single_block_saved_sp()
        clinic = self._arm_clinic(graph, blocks)
        cast(Any, clinic).function = SimpleNamespace(graph=graph, normalized=False)
        clinic._func_graph = graph  # pylint: disable=protected-access
        clinic._sp_shift = 0  # pylint: disable=protected-access
        clinic._fail_fast = False  # pylint: disable=protected-access
        clinic._sp_tracker_track_memory = False  # pylint: disable=protected-access
        stack_pointer_tracker = SimpleNamespace(inconsistent_for=mock.Mock(return_value=False))
        stack_pointer_tracker_analysis = mock.Mock(return_value=stack_pointer_tracker)
        cast(Any, clinic.project).analyses = SimpleNamespace(StackPointerTracker=stack_pointer_tracker_analysis)

        self.assertIs(clinic._track_stack_pointers(), stack_pointer_tracker)  # pylint: disable=protected-access

        _, tracked_regs = stack_pointer_tracker_analysis.call_args.args
        initial_reg_values = stack_pointer_tracker_analysis.call_args.kwargs["initial_reg_values"]
        r7_offset = clinic.project.arch.registers["r7"][0]
        self.assertNotIn(r7_offset, tracked_regs)
        self.assertNotIn(r7_offset, initial_reg_values)

    def test_arm_saved_sp_exception_clobber_uses_full_function_graph(self):
        entry_insns = [self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_SP)]
        clobber_insns = [self._arm_copy(capstone.arm.ARM_REG_R7, capstone.arm.ARM_REG_R11)]
        restore_insns = [self._arm_copy(capstone.arm.ARM_REG_SP, capstone.arm.ARM_REG_R7)]
        entry = BlockNode(0x1001, 2, thumb=True)
        handler = BlockNode(0x1101, 2, thumb=True)
        endpoint = BlockNode(0x1201, 2, thumb=True)
        full_graph = networkx.DiGraph()
        full_graph.add_edge(entry, endpoint)
        full_graph.add_edge(entry, handler, type="exception")
        full_graph.add_edge(handler, endpoint)
        filtered_graph = networkx.DiGraph([(entry, endpoint)])
        blocks = {
            entry.addr: self._arm_block(entry, entry_insns),
            handler.addr: self._arm_block(handler, clobber_insns),
            endpoint.addr: self._arm_block(endpoint, restore_insns),
        }
        clinic = self._arm_clinic(full_graph, blocks)
        cast(Any, clinic).function = SimpleNamespace(graph=full_graph, normalized=True)
        clinic._func_graph = filtered_graph  # pylint: disable=protected-access
        clinic._sp_shift = 0  # pylint: disable=protected-access
        clinic._fail_fast = False  # pylint: disable=protected-access
        clinic._sp_tracker_track_memory = False  # pylint: disable=protected-access
        stack_pointer_tracker = SimpleNamespace(inconsistent_for=mock.Mock(return_value=False))
        stack_pointer_tracker_analysis = mock.Mock(return_value=stack_pointer_tracker)
        cast(Any, clinic.project).analyses = SimpleNamespace(StackPointerTracker=stack_pointer_tracker_analysis)

        self.assertIs(clinic._track_stack_pointers(), stack_pointer_tracker)  # pylint: disable=protected-access

        _, tracked_regs = stack_pointer_tracker_analysis.call_args.args
        initial_reg_values = stack_pointer_tracker_analysis.call_args.kwargs["initial_reg_values"]
        r7_offset = clinic.project.arch.registers["r7"][0]
        self.assertNotIn(r7_offset, tracked_regs)
        self.assertNotIn(r7_offset, initial_reg_values)


if __name__ == "__main__":
    unittest.main()
