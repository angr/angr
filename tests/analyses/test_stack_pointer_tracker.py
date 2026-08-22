#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import archinfo

import angr
from angr import ailment
from angr.analyses.s_propagator import SPropagator
from angr.analyses.stack_pointer_tracker import Register as StackPointerRegister
from angr.code_location import AILCodeLocation
from angr.codenode import BlockNode, FuncNode
from angr.engines.pcode.cc import SimCCPCodeX86Win16NearPascal
from angr.knowledge_base import KnowledgeBase
from angr.sim_type import SimTypeFunction, SimTypeShort
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def run_tracker(track_mem, use_bp):
    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    p.analyses.CFGFast()
    main = p.kb.functions["main"]
    sp = p.arch.sp_offset
    regs = {sp}
    if use_bp:
        bp = p.arch.bp_offset
        regs.add(bp)
    sptracker = p.analyses.StackPointerTracker(main, regs, track_memory=track_mem)
    sp_result = sptracker.offset_after(0x4007D4, sp)
    if use_bp:
        bp_result = sptracker.offset_after(0x4007D4, bp)
        return sp_result, bp_result
    return sp_result


def init_tracker(p, func_addr: str | int, track_mem, cross_insn_opt: bool = True):
    p.analyses.CFGFast()
    main = p.kb.functions[func_addr]
    sp = p.arch.sp_offset
    regs = {sp}
    sptracker = p.analyses.StackPointerTracker(main, regs, track_memory=track_mem, cross_insn_opt=cross_insn_opt)
    return sptracker, sp


class TestStackPointerTracker(unittest.TestCase):
    @staticmethod
    def _pcode_x86_16_tracker(code: bytes, *, initial_sp_as_register: bool = False):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        block = project.factory.block(0, size=len(code))
        tracker = project.analyses.StackPointerTracker(
            None,
            {arch.sp_offset},
            block=block,
            track_memory=True,
            cross_insn_opt=False,
            initial_reg_values=(
                {arch.sp_offset: StackPointerRegister(arch.sp_offset, arch.bits)} if initial_sp_as_register else None
            ),
        )
        return arch, tracker

    @staticmethod
    def _pcode_x86_16_function_tracker(code: bytes):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        base = 0x1000
        project = angr.load_shellcode(
            code,
            arch=arch,
            load_address=base,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        cfg = project.analyses.CFGFast(
            function_starts=[base],
            regions=[(base, base + len(code))],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=True,
        )
        function = cfg.functions[base]
        tracker = project.analyses.StackPointerTracker(
            function,
            {arch.sp_offset},
            track_memory=True,
            cross_insn_opt=False,
        )
        return arch, function, tracker

    def test_stack_pointer_tracker(self):
        sp_result, bp_result = run_tracker(track_mem=True, use_bp=True)
        assert sp_result == 8
        assert bp_result == 0

    def test_stack_pointer_tracker_no_mem(self):
        sp_result, bp_result = run_tracker(track_mem=False, use_bp=True)
        assert sp_result == 8
        assert bp_result is None

    def test_stack_pointer_tracker_just_sp(self):
        sp_result = run_tracker(track_mem=False, use_bp=False)
        assert sp_result is None

    def test_stack_pointer_tracker_offset_block(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        sptracker, sp = init_tracker(p, "main", track_mem=False)
        sp_result = sptracker.offset_after_block(0x40071D, sp)
        assert sp_result is not None
        sp_result = sptracker.offset_after_block(0x400700, sp)
        assert sp_result is None
        sp_result = sptracker.offset_before_block(0x40071D, sp)
        assert sp_result is not None
        sp_result = sptracker.offset_before_block(0x400700, sp)
        assert sp_result is None

    def test_stack_pointer_tracker_offset_mask(self):
        # SPTracker should treat 0xfffffff8 as a bitmask
        proj = angr.Project(
            os.path.join(
                test_location, "i386", "windows", "39ca9900b5a1aaff6a218a56884f8c235263e3eb4e64c325b357fb028295f0a5"
            ),
            auto_load_libs=False,
        )
        sptracker, sp = init_tracker(proj, 0x401F3E, track_mem=False, cross_insn_opt=False)
        off_0 = sptracker.offset_after(0x401F41, sp)
        off_1 = sptracker.offset_before(0x401F47, sp)
        assert off_0 is not None
        print(off_1 - off_0)
        assert off_1 - off_0 == -0xC

    def test_pcode_x86_16_tracks_each_segment_register_push_and_pop(self):
        # push es; push ds; pop es; pop ds
        arch, tracker = self._pcode_x86_16_tracker(bytes.fromhex("061e071f"))
        sp = arch.sp_offset

        assert tracker.offset_before(0, sp) == 0
        assert tracker.offset_after(0, sp) == 0xFFFE
        assert tracker.offset_after(1, sp) == 0xFFFC
        assert tracker.offset_after(2, sp) == 0xFFFE
        assert tracker.offset_after(3, sp) == 0

    def test_pcode_x86_16_unknown_stack_pointer_writes_fail_closed(self):
        for code in (bytes.fromhex("01c4"), bytes.fromhex("21c4")):  # add sp, ax; and sp, ax
            with self.subTest(code=code.hex()):
                arch, tracker = self._pcode_x86_16_tracker(code)
                assert tracker.offset_before(0, arch.sp_offset) == 0
                assert tracker.offset_after(0, arch.sp_offset) is None

    def test_pcode_x86_16_dynamic_stack_displacement_is_unknown_but_consistent(self):
        # sub sp, dx; push ss; pop ds; ret
        arch, function, tracker = self._pcode_x86_16_function_tracker(bytes.fromhex("29d4161fc3"))

        assert tracker.offset_after_block(function.addr, arch.sp_offset) is None
        assert not tracker.inconsistent_for(arch.sp_offset)

    def test_pcode_x86_16_unrelated_stack_replacement_remains_inconsistent(self):
        # mov sp, dx; ret -- unlike an arithmetic displacement, this destroys all SP provenance.
        arch, _, tracker = self._pcode_x86_16_function_tracker(bytes.fromhex("89d4c3"))

        assert tracker.inconsistent_for(arch.sp_offset)

    def test_pcode_x86_16_subtracts_from_a_symbolic_register_initial_value(self):
        arch, tracker = self._pcode_x86_16_tracker(bytes.fromhex("16"), initial_sp_as_register=True)  # push ss
        assert tracker.offset_after(0, arch.sp_offset) == 0xFFFE

    def test_sprop_intra_instruction_stack_adjustment_requires_the_same_ail_block(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            b"\xc3",
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        propagator = object.__new__(SPropagator)
        propagator.project = project

        sp_entry = ailment.Expr.VirtualVariable(
            0, 0, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        sp_after = ailment.Expr.VirtualVariable(
            1, 1, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        subtraction = ailment.Expr.BinaryOp(
            2,
            "Sub",
            (sp_entry, ailment.Expr.Const(3, 2, 16)),
            False,
            bits=16,
        )
        definition = ailment.Stmt.Assignment(4, sp_after, subtraction, ins_addr=0x100)
        defining_block = ailment.Block(0x100, 2, statements=[definition], idx=1)
        defloc = AILCodeLocation(0x100, 1, 0, 0x100)

        helper = propagator._stack_pointer_adjustment_within_instruction
        assert (
            helper(
                sp_after,
                AILCodeLocation(0x100, 1, 1, 0x100),
                {sp_after.varid: (sp_after, defloc)},
                {(0x100, 1): defining_block},
            )
            == -2
        )
        assert (
            helper(
                sp_after,
                AILCodeLocation(0x100, 2, 1, 0x100),
                {sp_after.varid: (sp_after, defloc)},
                {(0x100, 1): defining_block},
            )
            == 0
        )

    def test_sprop_block_head_stack_phi_uses_the_tracked_instruction_entry_value(self):
        class EntryStackPointerTracker:
            @staticmethod
            def offset_before(_ins_addr, _reg_offset):
                return 0xFFFC

        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            b"\xc3",
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        incoming_a = ailment.Expr.VirtualVariable(
            0, 0, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        incoming_b = ailment.Expr.VirtualVariable(
            1, 1, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        merged_sp = ailment.Expr.VirtualVariable(
            2, 2, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        block = ailment.Block(
            0x100,
            1,
            statements=[
                ailment.Stmt.Assignment(
                    3,
                    merged_sp,
                    ailment.Expr.Phi(
                        4,
                        16,
                        [((0x80, None), incoming_a), ((0x90, None), incoming_b)],
                        ins_addr=0x100,
                    ),
                    ins_addr=0x100,
                ),
                ailment.Stmt.Store(
                    5,
                    merged_sp,
                    ailment.Expr.Const(6, 1, 8),
                    1,
                    "Iend_LE",
                    ins_addr=0x100,
                ),
            ],
        )
        propagator = SPropagator(
            project,
            block,
            ail_manager=ailment.Manager(arch=arch),
            stack_pointer_tracker=EntryStackPointerTracker(),
        )

        replacement = propagator.replacements[AILCodeLocation(0x100, None, 1, 0x100)][merged_sp]
        assert isinstance(replacement, ailment.Expr.StackBaseOffset)
        assert replacement.offset == -4

    def test_sprop_sign_extends_a_narrow_stack_pointer_offset_to_the_architecture_width(self):
        class EntryStackPointerTracker:
            @staticmethod
            def offset_before(_ins_addr, _reg_offset):
                return 0

        arch = archinfo.ArchPcode("avr8:LE:16:extended")
        project = angr.load_shellcode(
            b"\x00\x00",
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=1,
        )
        sp_bits = arch.registers["sp"][1] * arch.byte_width
        sp_entry = ailment.Expr.VirtualVariable(
            0, 0, sp_bits, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        sp_after = ailment.Expr.VirtualVariable(
            1, 1, sp_bits, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        subtraction = ailment.Expr.BinaryOp(
            2,
            "Sub",
            (sp_entry, ailment.Expr.Const(3, 2, sp_bits)),
            False,
            bits=sp_bits,
        )
        block = ailment.Block(
            0,
            2,
            statements=[
                ailment.Stmt.Assignment(4, sp_after, subtraction, ins_addr=0),
                ailment.Stmt.Store(
                    5,
                    sp_after,
                    ailment.Expr.Const(6, 1, 8),
                    1,
                    "Iend_LE",
                    ins_addr=0,
                ),
            ],
        )
        propagator = SPropagator(
            project,
            block,
            ail_manager=ailment.Manager(arch=arch),
            stack_pointer_tracker=EntryStackPointerTracker(),
        )

        replacement = propagator.replacements[AILCodeLocation(0, None, 1, 0)][sp_after]
        assert isinstance(replacement, ailment.Expr.StackBaseOffset)
        assert replacement.bits == sp_bits == sp_after.bits
        assert replacement.offset == -2

    def test_pcode_mips_64_stack_pointer_uses_canonical_register_width(self):
        # daddiu sp, sp, -0x10; nop
        code = bytes.fromhex("f0ffbd6700000000")
        arch = archinfo.ArchPcode("MIPS:LE:64:64-32addr")
        project = angr.load_shellcode(
            code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=1,
        )
        machine_block = project.factory.block(0, size=len(code))
        tracker = project.analyses.StackPointerTracker(
            None,
            {arch.sp_offset},
            block=machine_block,
            track_memory=True,
            cross_insn_opt=False,
        )

        expected = 0xFFFF_FFFF_FFFF_FFF0
        assert tracker.offset_after(0, arch.sp_offset) == expected
        assert tracker.offset_before(4, arch.sp_offset) == expected

        sp_bits = arch.registers["sp"][1] * arch.byte_width
        sp_value = ailment.Expr.VirtualVariable(
            0, 0, sp_bits, ailment.Expr.VirtualVariableCategory.REGISTER, oident=arch.sp_offset
        )
        ail_block = ailment.Block(
            4,
            4,
            statements=[
                ailment.Stmt.Store(
                    1,
                    sp_value,
                    ailment.Expr.Const(2, 1, 8),
                    1,
                    "Iend_LE",
                    ins_addr=4,
                )
            ],
        )
        propagator = SPropagator(
            project,
            ail_block,
            ail_manager=ailment.Manager(arch=arch),
            stack_pointer_tracker=tracker,
        )
        replacement = propagator.replacements[AILCodeLocation(4, None, 0, 4)][sp_value]
        assert isinstance(replacement, ailment.Expr.StackBaseOffset)
        assert replacement.bits == sp_bits == sp_value.bits
        assert replacement.offset == -0x10

    def test_pcode_x86_16_restores_exact_call_instruction_return_frames(self):
        cases = (
            bytes.fromhex("e80200"),  # near call
            bytes.fromhex("9a78563412"),  # direct CALLF
            bytes.fromhex("36ff1e2000"),  # indirect CALLF SS:[0x20]
        )
        for code in cases:
            with self.subTest(code=code.hex()):
                arch, tracker = self._pcode_x86_16_tracker(code)
                assert tracker.offset_before(0, arch.sp_offset) == 0
                assert tracker.offset_after(0, arch.sp_offset) == 0

        # A call to its own fallthrough is the classic get-IP idiom. The lifter deliberately classifies it as
        # ordinary flow, so its pushed return word remains on the stack instead of being guessed into a returned call.
        arch, tracker = self._pcode_x86_16_tracker(bytes.fromhex("e80000"))
        assert tracker.offset_after(0, arch.sp_offset) == 0xFFFE

    def test_pcode_callee_lookup_uses_the_function_knowledge_base(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            bytes.fromhex("e80100c3c3"),
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        function_kb = KnowledgeBase(project)
        caller = function_kb.functions.function(addr=0, create=True)
        callee = function_kb.functions.function(addr=4, create=True)
        assert caller is not None and callee is not None

        call_block = BlockNode(0, 3, bytestr=bytes.fromhex("e80100"))
        caller._register_node(True, call_block)  # pylint:disable=protected-access
        caller.transition_graph.add_edge(
            call_block,
            FuncNode(callee.addr),
            type="call",
            outside=False,
            ins_addr=0,
            stmt_idx=None,
        )
        caller.normalized = True
        callee.calling_convention = SimCCPCodeX86Win16NearPascal(arch)
        callee.prototype = SimTypeFunction([SimTypeShort()], SimTypeShort()).with_arch(arch)

        # The analysis deliberately runs with the project's default KB. The call edge and callee ABI belong to the
        # function's separate KB, which is the only authoritative source for this transition graph.
        tracker = project.analyses.StackPointerTracker(
            caller,
            {arch.sp_offset},
            kb=project.kb,
            track_memory=True,
            cross_insn_opt=False,
        )
        assert tracker.offset_after(0, arch.sp_offset) == 2


if __name__ == "__main__":
    logging.getLogger("angr.analyses.stack_pointer_tracker").setLevel(logging.INFO)
    unittest.main()
