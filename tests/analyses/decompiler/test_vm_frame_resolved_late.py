#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.statement import Store
from angr.analyses.decompiler.clinic import ClinicStage

BASE = 0x400000

# mov rbx, rsp; test edi, edi; je L1
# mov r9, rsp; sub r9, 0x48; and r9b, 0xf0; mov rsp, r9; jmp J
# L1: mov r9, rsp; sub r9, 0x58; and r9b, 0xf0; add r9, 0x10; mov rsp, r9
# J: lea rax, [rsp+0x30]; mov [rsp+8], rax; mov rdx, [rsp+8]; mov [rdx-8], rsi; mov [rdx-0x10], rdi;
# <tail>; mov rsp, rbx; ret
HEAD = bytes.fromhex(
    "4889e385ff74104989e14983e9484180e1f04c89cceb124989e14983e9584180e1f04983c1104c89cc"
    "488d4424304889442408488b542408488972f848897af0"
)
RET = bytes.fromhex("4889dcc3")
# xor eax, eax
TAIL_PRIVATE = bytes.fromhex("31c0")
# lea rax, [rsp+8]  (returns the slot's address: it escapes)
TAIL_ESCAPE = bytes.fromhex("488d442408")


def _pre_ssa_stores(code: bytes) -> list[Store]:
    proj = angr.load_shellcode(code, "AMD64", load_address=BASE)
    cfg = proj.analyses.CFGFast(normalize=True)
    clinic = proj.analyses.Clinic(
        proj.kb.functions[BASE],
        vm_deobfuscation=True,
        end_stage=ClinicStage.PRE_SSA_LEVEL1_SIMPLIFICATIONS,
        cfg=cfg.model,
    )
    return [stmt for block in clinic.graph for stmt in block.statements if isinstance(stmt, Store)]


class TestVMFrameResolvedLate(unittest.TestCase):
    def test_dead_frame_slot_store_once_the_aligned_frame_is_resolved(self):
        # the frame is aligned through a partial register (an Insert StackPointerTracker cannot follow); only after
        # simplification is the slot holding the frame pointer known to be dead
        assert _pre_ssa_stores(HEAD + TAIL_PRIVATE + RET) == []

    def test_escaping_slot_store_is_kept(self):
        stores = _pre_ssa_stores(HEAD + TAIL_ESCAPE + RET)
        assert len(stores) == 1, stores


if __name__ == "__main__":
    unittest.main()
