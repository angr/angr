#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import angr
from angr.ailment import Manager
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Extract,
    Insert,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.analyses.decompiler.ail_simplifier import AILSimplifier


class TestSSAOverlappingStackWrites(unittest.TestCase):
    def test_partial_write_into_slot_overlapping_another(self):
        # a VMProtect NOR on 4-byte-offset 8-byte slots: the dword store at rsp-0x34 keeps rsp-0x30..-0x2c, which
        # belongs to the slot at rsp-0x30, not to the 8-byte slot at rsp-0x38 that covers rsp-0x34
        code = bytes.fromhex(
            "894c24d0"  # mov [rsp-0x30], ecx
            "48897c24c8"  # mov [rsp-0x38], rdi
            "c74424cc11111111"  # mov dword [rsp-0x34], 0x11111111
            "897424c8"  # mov [rsp-0x38], esi
            "48f75424c8"  # not qword [rsp-0x38]
            "8b4424c8"  # mov eax, [rsp-0x38]
            "250f0f0f0f"  # and eax, 0x0f0f0f0f
            "894424cc"  # mov [rsp-0x34], eax
            "48895424c4"  # mov [rsp-0x3c], rdx
            "48f75424cc"  # not qword [rsp-0x34]
            "8b4424cc"  # mov eax, [rsp-0x34]
            "214424d0"  # and [rsp-0x30], eax
            "488b4424d0"  # mov rax, [rsp-0x30]
            "c3"
        )
        proj = angr.load_shellcode(code, arch="amd64")
        proj.vm_deobfuscation = True
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions[0], cfg=cfg.model, fail_fast=True, vm_deobfuscation=True)
        assert dec.codegen is not None
        text = dec.codegen.text
        # 0x11111111 is overwritten before it is read; 0xeeeeeeee is the stale high half of the 8-byte not at rsp-0x38
        assert "0x11111111" not in text and "1111111100000000" not in text
        assert "0xeeeeeeee" not in text
        assert "0xf0f0f0f" in text

    def test_partial_write_whose_kept_bytes_are_overwritten(self):
        # the dword write keeps the high half of the qword slot; the next write overwrites it and the dword read gets
        # the low half back: no Insert survives
        code = bytes.fromhex(
            "48897c24c8"  # mov [rsp-0x38], rdi
            "897424c8"  # mov [rsp-0x38], esi
            "8b4424c8"  # mov eax, [rsp-0x38]
            "c74424cc00000000"  # mov dword [rsp-0x34], 0
            "488b4c24c8"  # mov rcx, [rsp-0x38]
            "4801c8"  # add rax, rcx
            "c3"
        )
        proj = angr.load_shellcode(code, arch="amd64")
        proj.vm_deobfuscation = True
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions[0], cfg=cfg.model, fail_fast=True, vm_deobfuscation=True)
        assert dec.codegen is not None
        assert "_INSERT" not in dec.codegen.text

    def test_merge_inserts(self):
        manager = Manager()
        stub = SimpleNamespace(_ail_manager=manager)

        def vvar(varid, bits=64):
            return VirtualVariable(manager.next_atom(), varid, bits, VirtualVariableCategory.STACK, -56)

        def const(v, bits=64):
            return Const(manager.next_atom(), v, bits)

        def extract(base, bits, off):
            return Extract(manager.next_atom(), bits, base, const(off), "Iend_LE")

        def insert(base, off, value):
            return Insert(manager.next_atom(), base, const(off), value, "Iend_LE")

        a = vvar(1)
        # the halves of one variable put back together
        merged = AILSimplifier._merge_inserts(
            stub, insert(vvar(2), 0, extract(a, 32, 0)), insert(vvar(3), 4, extract(a, 32, 4))
        )
        assert isinstance(merged, VirtualVariable) and merged.varid == 1
        # disjoint halves of different values: a Concat, high part first
        x, y = vvar(4, 32), vvar(5, 32)
        merged = AILSimplifier._merge_inserts(stub, insert(vvar(2), 4, x), insert(vvar(3), 0, y))
        assert isinstance(merged, BinaryOp) and merged.op == "Concat"
        assert merged.operands[0].varid == 4 and merged.operands[1].varid == 5
        # the outer write covers the inner one: the inner base stays
        merged = AILSimplifier._merge_inserts(stub, insert(vvar(2), 0, vvar(6, 16)), insert(vvar(3), 0, y))
        assert isinstance(merged, Insert) and merged.base.varid == 2 and merged.value.varid == 5
        # partial overlap: no merge
        assert AILSimplifier._merge_inserts(stub, insert(vvar(2), 2, x), insert(vvar(3), 0, y)) is None
        # an aggregate keeps its partial writes (a spilled Go string header: ptr, then len)
        p, n = vvar(7), vvar(8)
        assert AILSimplifier._merge_inserts(stub, insert(vvar(2, 128), 0, p), insert(vvar(3, 128), 8, n)) is None


if __name__ == "__main__":
    unittest.main()
