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

    def test_callee_cleanup_with_function_callee_node(self):
        # VM deobfuscation registers the callee Function itself as the call target node.
        # push 0 (x2); call 0x400010; ret | 0x400010: ret 8
        code = b"\x6a\x00" * 2 + b"\xe8\x0b\x00\x00\x00\xc3" + b"\x90" * 6 + b"\xc2\x08\x00"
        p = angr.load_shellcode(code, "x86", load_address=0x400000)
        callee = p.kb.functions.function(0x400010, create=True)
        callee.calling_convention = SimCCStdcall(p.arch)
        callee.prototype = SimTypeFunction([SimTypeInt()] * 2, SimTypeInt()).with_arch(p.arch)
        func = angr.knowledge_plugins.Function(p.kb.functions, 0x400000, "f")
        p.kb.functions[func.addr] = func
        call_block, ret_block = p.factory.snippet(0x400000, size=9), p.factory.snippet(0x400009, size=1)
        func.call_to(call_block, callee, ret_block)
        func.return_from_call(callee, ret_block)
        func.normalized = True  # as in a deobfuscated graph; normalizing a copy would replace the Function node
        spt = p.analyses.StackPointerTracker(func, {p.arch.sp_offset})
        assert _signed32(spt.offset_before(0x400009, p.arch.sp_offset)) == 0

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

    def test_call_sp_adjustments_without_a_known_sp(self):
        # and esp, eax; push 0 (x2); call eax; push 0; call ebx; ret
        p, func = _load_x86_shellcode(b"\x21\xc4" + b"\x6a\x00" * 2 + b"\xff\xd0" + b"\x6a\x00\xff\xd3" + b"\xc3")
        csp = p.kb.callsite_prototypes
        csp.set_prototype(
            0x400000, SimCCStdcall(p.arch), SimTypeFunction([SimTypeInt()] * 2, SimTypeInt()).with_arch(p.arch)
        )
        csp.set_prototype(
            0x400008, SimCCMicrosoftCdecl(p.arch), SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(p.arch)
        )
        spt = p.analyses.StackPointerTracker(func, {p.arch.sp_offset})
        assert spt.offset_before(0x400008, p.arch.sp_offset) is None
        # ret pop + callee cleanup, known even though sp is not
        assert spt.call_sp_adjustments == {0x400006: 4 + 8, 0x40000A: 4}

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

    @staticmethod
    def _block_tracker(code: bytes, regs=(), **kwargs):
        proj = angr.load_shellcode(code, "AMD64", start_offset=0, load_address=0x1000)
        block = proj.factory.block(0x1000, len(code))
        sp = proj.arch.sp_offset
        tracked = {sp} | {proj.arch.registers[r][0] for r in regs}
        spt = proj.analyses.StackPointerTracker(
            None, tracked, block=block, track_memory=True, cross_insn_opt=False, **kwargs
        )
        return spt.offset_after(block.instruction_addrs[-1], sp)

    def test_exact_alignment(self):
        abi = bytes.fromhex("4883ec24" "4883e4f0")  # sub rsp, 0x24; and rsp, -16
        wide = bytes.fromhex("4883ec24" "4883e4e0")  # sub rsp, 0x24; and rsp, -32
        # rsp + 8 is 16-aligned on entry: rsp - 0x24 is 4 above a multiple of 16
        assert self._block_tracker(abi, entry_sp_alignment=(16, 8)) == (-0x28) & (2**64 - 1)
        # a 32-byte mask leaves a gap of 4 or 20
        assert self._block_tracker(wide, entry_sp_alignment=(16, 8)) is None
        # by default the mask is ignored
        assert self._block_tracker(abi) == (-0x24) & (2**64 - 1)
        assert self._block_tracker(wide) == (-0x24) & (2**64 - 1)
        # a word mask on x86 is exact
        word = bytes.fromhex("83ec26" "83e4fc")  # sub esp, 0x26; and esp, -4
        proj = angr.load_shellcode(word, "x86", start_offset=0, load_address=0x1000)
        block = proj.factory.block(0x1000, len(word))
        sp = proj.arch.sp_offset
        for known, expected in (((4, 0), -0x28), (None, -0x26)):
            spt = proj.analyses.StackPointerTracker(
                None, {sp}, block=block, track_memory=True, cross_insn_opt=False, entry_sp_alignment=known
            )
            assert spt.offset_after(block.instruction_addrs[-1], sp) == expected & 0xFFFFFFFF

    def test_vmprotect_not_add_not(self):
        # rsp = ~(~rsp + 0x38) == rsp - 0x38, with ~rsp computed as a NOR of two stack copies of rsp
        code = bytes.fromhex(
            "48896424f8"  # mov [rsp-8], rsp
            "48896424f0"  # mov [rsp-16], rsp
            "488b4424f8"  # mov rax, [rsp-8]
            "488b4c24f0"  # mov rcx, [rsp-16]
            "48f7d0"  # not rax
            "48f7d1"  # not rcx
            "4821c8"  # and rax, rcx
            "4883c038"  # add rax, 0x38
            "48f7d0"  # not rax
            "4889c4"  # mov rsp, rax
        )
        assert self._block_tracker(code, ("rax", "rcx")) == (-0x38) & (2**64 - 1)

    def test_vmprotect_nor_of_offsets(self):
        # rsp = ~rax & ~rcx with rax == rcx == ~(rsp - 0x38) (VMProtect ultra's NOR)
        code = bytes.fromhex(
            "4889e0"  # mov rax, rsp
            "4883e838"  # sub rax, 0x38
            "48f7d0"  # not rax
            "4889c1"  # mov rcx, rax
            "48f7d0"  # not rax
            "48f7d1"  # not rcx
            "4821c8"  # and rax, rcx
            "4889c4"  # mov rsp, rax
        )
        assert self._block_tracker(code, ("rax", "rcx")) == (-0x38) & (2**64 - 1)

    def test_vmprotect_shift_by_zero(self):
        # devirtualized VMProtect blocks are unoptimized IR and copy sp through shifts by zero
        def sp_after(code: bytes):
            proj = angr.load_shellcode(code, "AMD64", start_offset=0, load_address=0x1000)
            irsb = pyvex.lift(code, 0x1000, proj.arch, opt_level=0, cross_insn_opt=False)

            class _Node:
                addr = 0x1000
                size = len(code)

            node = _Node()
            node.irsb = irsb
            node.instruction_addrs = list(irsb.instruction_addresses)
            sp = proj.arch.sp_offset
            tracked = {sp, proj.arch.registers["rax"][0]}
            spt = proj.analyses.StackPointerTracker(None, tracked, block=node, track_memory=True, cross_insn_opt=False)
            return spt.offset_after(node.instruction_addrs[-1], sp)

        for shift in ("48c1e000", "48c1e800", "48c1f800"):  # shl/shr/sar rax, 0
            # mov rax, rsp; <shift>; sub rax, 0x38; mov rsp, rax
            code = bytes.fromhex("4889e0" + shift + "4883e838" "4889c4")
            assert sp_after(code) == (-0x38) & (2**64 - 1)
        # a shift by a nonzero amount stays unknown
        assert sp_after(bytes.fromhex("4889e0" "48c1e001" "4889c4")) is None

    def test_store_of_unknown_value_replaces_slot(self):
        code = bytes.fromhex(
            "48896424f8"  # mov [rsp-8], rsp
            "48897c24f8"  # mov [rsp-8], rdi
            "488b6424f8"  # mov rsp, [rsp-8]
        )
        assert self._block_tracker(code) is None


if __name__ == "__main__":
    logging.getLogger("angr.analyses.stack_pointer_tracker").setLevel(logging.INFO)
    unittest.main()
