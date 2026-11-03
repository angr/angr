#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

import angr
from angr.engines.vex.light.light import VEXMixin


class _Eng:
    pass


for _name in ("_vip_popped_regs", "_vip_block_reg_writes", "_vip_canonical_reg_name", "_ctf_canonical_reg_name"):
    setattr(_Eng, _name, getattr(VEXMixin, _name))


def _eng(arch, code, popped=()):
    proj = angr.load_shellcode(code, arch, load_address=0x1000)
    eng = _Eng()
    eng.project = proj
    eng.state = types.SimpleNamespace(globals={"cur_bbl": proj.factory.block(0x1000), "vip_popped_regs": popped})
    return eng


class TestVipPoppedRegs(unittest.TestCase):
    def test_amd64_vm_exit(self):
        # pop rsi; pop rax; lea r8, [rax-1]; pop rbx; mov ebx, ecx; xchg r12d, ebp; pop rdx
        eng = _eng("amd64", bytes.fromhex("5e58" "4c8d40ff" "5b" "89cb" "4487e5" "5a"), popped=frozenset({"rbp", "rdi"}))
        assert eng._vip_popped_regs() == {"rsi", "rax", "rdi", "rdx"}
        # before the mov: rbx still holds its popped value
        assert eng._vip_popped_regs(0x1000 + 7) == {"rsi", "rax", "rbx", "rbp", "rdi"}
        assert eng._vip_popped_regs(0x1000) == {"rbp", "rdi"}

    def test_i386_partial_write(self):
        # pop esi; mov si, ax; pop edi; inc edi: a 16-bit write keeps most of the popped value
        eng = _eng("x86", bytes.fromhex("5e" "6689c6" "5f" "47"))
        assert eng._vip_popped_regs() == {"esi"}
        assert eng._vip_popped_regs(0x1000 + 5) == {"esi", "edi"}

    def test_amd64_partial_write(self):
        # pop rcx; and cl, 5; dec ch; mov ecx, eax
        eng = _eng("amd64", bytes.fromhex("59" "80e105" "fecd" "89c1"))
        assert eng._vip_popped_regs(0x1000 + 6) == {"rcx"}
        assert eng._vip_popped_regs() == set()


if __name__ == "__main__":
    unittest.main()
