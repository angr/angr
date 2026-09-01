#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import pyvex

import angr
from angr.calling_conventions import SimCCMicrosoftCdecl, SimCCStdcall
from angr.sim_type import SimTypeDouble, SimTypeFunction, SimTypeInt
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


def init_tracker(p, func_addr: str | int, track_mem, cross_insn_opt: bool = True, scope_window: int = 0x2000):
    if isinstance(func_addr, int):
        # StackPointerTracker only walks the one function, so recovering the whole binary is wasted work
        p.analyses.CFGFast(
            regions=[(func_addr, func_addr + scope_window)],
            start_at_entry=False,
            function_starts=[func_addr],
            force_smart_scan=False,
        )
    else:
        p.analyses.CFGFast()
    main = p.kb.functions[func_addr]
    sp = p.arch.sp_offset
    regs = {sp}
    sptracker = p.analyses.StackPointerTracker(main, regs, track_memory=track_mem, cross_insn_opt=cross_insn_opt)
    return sptracker, sp


def _signed32(v: int | None) -> int:
    assert v is not None
    return v - (1 << 32) if v >= (1 << 31) else v


def _load_x86_shellcode(code: bytes):
    p = angr.load_shellcode(code, "x86", load_address=0x400000)
    p.analyses.CFGFast(normalize=True)
    return p, p.kb.functions[0x400000]


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

    def test_indirect_callsite_prototype_cleanup(self):
        # issue #7289. sub esp,16; push 0 (x6); call eax; add esp,16; ret
        code = b"\x83\xec\x10" + b"\x6a\x00" * 6 + b"\xff\xd0\x83\xc4\x10\xc3"
        after_call, ret = 0x400011, 0x400014

        cases = ["cdecl", "known-callee", "inferred", "manual", "manual-overrides-cdecl", "known-cdecl-callee"]
        for kind in cases:
            with self.subTest(kind=kind):
                p, func = _load_x86_shellcode(code)
                proto = SimTypeFunction([SimTypeInt()] * 6, SimTypeInt()).with_arch(p.arch)
                stdcall, cdecl = SimCCStdcall(p.arch), SimCCMicrosoftCdecl(p.arch)
                csp = p.kb.callsite_prototypes
                if kind == "cdecl":
                    csp.set_prototype(0x400000, cdecl, proto)
                elif kind == "known-callee":
                    callee = p.kb.functions[func.get_call_target(0x400000)]
                    callee.calling_convention, callee.prototype = stdcall, proto
                elif kind == "inferred":
                    csp.set_prototype(0x400000, stdcall, proto)
                elif kind == "manual":
                    csp.set_prototype(0x400000, stdcall, proto, manual=True)
                elif kind == "manual-overrides-cdecl":
                    csp.set_prototype(0x400000, cdecl, proto)
                    csp.set_prototype(0x400000, stdcall, proto, manual=True)
                elif kind == "known-cdecl-callee":
                    # a known callee takes precedence over an inferred call-site prototype
                    callee = p.kb.functions[func.get_call_target(0x400000)]
                    callee.calling_convention, callee.prototype = cdecl, proto
                    csp.set_prototype(0x400000, stdcall, proto)

                spt = p.analyses.StackPointerTracker(func, {p.arch.sp_offset})
                expected = (-40, -24) if kind in {"cdecl", "known-cdecl-callee"} else (-16, 0)
                sp = p.arch.sp_offset
                assert (
                    _signed32(spt.offset_before(after_call, sp)),
                    _signed32(spt.offset_before(ret, sp)),
                ) == expected

    def test_callee_cleanup_wide_stack_args(self):
        # stdcall f(double, int) pops 12 bytes. push 0 (x3); call eax; ret
        p, func = _load_x86_shellcode(b"\x6a\x00" * 3 + b"\xff\xd0\xc3")
        proto = SimTypeFunction([SimTypeDouble(), SimTypeInt()], SimTypeInt()).with_arch(p.arch)
        p.kb.callsite_prototypes.set_prototype(0x400000, SimCCStdcall(p.arch), proto)
        spt = p.analyses.StackPointerTracker(func, {p.arch.sp_offset})
        assert _signed32(spt.offset_before(0x400008, p.arch.sp_offset)) == 0

    def test_distinct_indirect_callsites(self):
        # push 0 (x2); call eax; push 0; call ebx; add esp,4; ret
        p, func = _load_x86_shellcode(b"\x6a\x00" * 2 + b"\xff\xd0" + b"\x6a\x00\xff\xd3" + b"\x83\xc4\x04\xc3")
        assert sorted(func.get_call_sites()) == [0x400000, 0x400006]
        csp = p.kb.callsite_prototypes
        csp.set_prototype(
            0x400000, SimCCStdcall(p.arch), SimTypeFunction([SimTypeInt()] * 2, SimTypeInt()).with_arch(p.arch)
        )
        csp.set_prototype(
            0x400006, SimCCMicrosoftCdecl(p.arch), SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(p.arch)
        )
        spt = p.analyses.StackPointerTracker(func, {p.arch.sp_offset})
        sp = p.arch.sp_offset
        assert _signed32(spt.offset_before(0x400006, sp)) == 0
        assert _signed32(spt.offset_before(0x40000A, sp)) == -4
        assert _signed32(spt.offset_before(0x40000D, sp)) == 0

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
