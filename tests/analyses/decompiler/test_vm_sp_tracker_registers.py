#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

import angr
from tests.common import print_decompilation_result

BASE = 0x400000


def _decompile(code: bytes, vm_deobfuscation: bool = False):
    proj = angr.load_shellcode(code, "AMD64", load_address=BASE)
    cfg = proj.analyses.CFGFast(normalize=True)
    dec = proj.analyses.Decompiler(
        proj.kb.functions[BASE], cfg=cfg.model, vm_deobfuscation=vm_deobfuscation, fail_fast=True
    )
    assert dec.codegen is not None and dec.codegen.text is not None and dec.clinic is not None
    print_decompilation_result(dec)
    return proj, dec


def _s64(v: int) -> int:
    return v - (1 << 64) if v >= (1 << 63) else v


class TestVMSpTrackerRegisters(unittest.TestCase):
    def test_sp_computed_from_a_scratch_register(self):
        # lea rax, [rsp-0x28]; mov rsp, rax; mov [rsp+8], rdi; mov [rsp+0x10], rsi; mov rax, [rsp+8];
        # add rax, [rsp+0x10]; add rsp, 0x28; ret
        code = bytes.fromhex("488d4424d84889c448897c24084889742410488b44240848034424104883c428c3")
        for vm_deobfuscation in (False, True):
            proj, dec = _decompile(code, vm_deobfuscation=vm_deobfuscation)
            spt = dec.clinic._spt
            sp = proj.arch.sp_offset
            if vm_deobfuscation:
                assert not spt.inconsistent_for(sp)
                assert _s64(spt.offset_before(0x400008, sp)) == -0x28
                assert _s64(spt.offset_before(0x400020, sp)) == 0
            else:
                # rax is only tracked for VM bodies
                assert spt.offset_before(0x400008, sp) is None
            assert re.search(r"return a0 \+ a1;", dec.codegen.text) is not None

    def test_scratch_registers_start_unknown(self):
        # xchg rsi, rsp; mov rax, [rsp]; xchg rsi, rsp; ret
        # rsi holds the second argument, not a stack address, so rsp is unknown between the two swaps
        code = bytes.fromhex("4887e6488b04244887e6c3")
        proj, dec = _decompile(code, vm_deobfuscation=True)
        spt = dec.clinic._spt
        sp = proj.arch.sp_offset
        assert spt.offset_before(0x400003, sp) is None
        assert spt.offset_before(0x40000A, sp) == 0
        assert re.search(r"return \*a1;", dec.codegen.text) is not None

    def test_unknown_sp_version_is_not_resolved_at_a_later_use(self):
        # mov rbx, rsp; xchg rsi, rsp; mov rax, [rsp]; mov rsp, rbx; ret
        # the load is folded into the return, after sp is known again; its address is still the unknown rsp
        code = bytes.fromhex("4889e34887e6488b04244889dcc3")
        proj, dec = _decompile(code)
        spt = dec.clinic._spt
        sp = proj.arch.sp_offset
        assert spt.offset_after(0x400003, sp) is None
        assert spt.offset_before(0x40000D, sp) == 0
        assert re.search(r"return \*a1;", dec.codegen.text) is not None


if __name__ == "__main__":
    unittest.main()
