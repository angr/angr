#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import pyvex

import angr
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

    def test_synthesized_node_with_nonlinear_insn_addrs(self):
        # A VM-deobfuscated node carries its own IRSB whose instruction addresses are synthetic: they
        # neither fall inside [node.addr, node.addr + size) nor increase. Per-instruction queries must
        # still resolve.
        code = b"\x55\x48\x83\xec\x20\x53\x48\x89\xe0"  # push rbp; sub rsp,0x20; push rbx; mov rax,rsp
        proj = angr.load_shellcode(code, "AMD64", start_offset=0, load_address=0x1000)
        irsb = pyvex.lift(code, 0x1000, proj.arch, opt_level=0, cross_insn_opt=False)

        block_addr = 0x7000000000090000
        insn_addrs = [block_addr, 0x7000000000030005, 0x7000000000010008, 0x7000000000250009]
        idx = 0
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.IMark):
                stmt.addr = insn_addrs[idx]
                stmt.delta = 0
                idx += 1
        assert idx == len(insn_addrs)
        irsb._instruction_addresses = None

        class _SynthesizedNode:
            def __init__(self):
                self.addr = block_addr
                self.size = len(code)
                self.irsb = irsb
                self.instruction_addrs = list(irsb.instruction_addresses)

        node = _SynthesizedNode()
        sp = proj.arch.sp_offset
        spt = proj.analyses.StackPointerTracker(None, {sp}, block=node, track_memory=False, cross_insn_opt=False)

        def u64(v):
            return v & (2**64 - 1)

        assert spt.offset_before(insn_addrs[0], sp) == 0
        assert spt.offset_after(insn_addrs[0], sp) == u64(-8)
        assert spt.offset_before(insn_addrs[1], sp) == u64(-8)
        assert spt.offset_after(insn_addrs[1], sp) == u64(-0x28)
        assert spt.offset_before(insn_addrs[2], sp) == u64(-0x28)
        assert spt.offset_after(insn_addrs[2], sp) == u64(-0x30)
        assert spt.offset_before(insn_addrs[3], sp) == u64(-0x30)
        assert spt.offset_before_block(block_addr, sp) == 0
        assert spt.offset_after_block(block_addr, sp) == u64(-0x30)


if __name__ == "__main__":
    logging.getLogger("angr.analyses.stack_pointer_tracker").setLevel(logging.INFO)
    unittest.main()
