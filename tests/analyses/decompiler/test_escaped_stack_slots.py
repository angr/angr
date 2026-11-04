#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import re
import unittest

import angr
from angr.ailment.expression import Phi
from angr.ailment.statement import Assignment
from angr.utils.ssa import clobber_def_vvars
from tests.common import bin_location


def _decompile(code: bytes):
    proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0)
    cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=False)
    proj.analyses.CompleteCallingConventions(recover_variables=False)
    dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg, fail_fast=True)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec


class TestEscapedStackSlots(unittest.TestCase):
    """
    A callee may write a stack variable whose address it was given. A read of the variable after the call must not
    resolve to the definition before the call.
    """

    def test_read_after_call_through_escaped_address(self):
        # _start(n): lz = n - 4; helper(&lz); if (lz != n - 4) warn(3);    helper(p): *p = 7; return 1
        #   push rbx; sub rsp, 0x10; lea ebx, [rdi-4]; mov [rsp+0xc], ebx; lea rdi, [rsp+0xc]; call helper
        #   cmp [rsp+0xc], ebx; je L; mov edi, 3; call warn; L: add rsp, 0x10; pop rbx; ret
        # helper: mov dword [rdi], 7; mov eax, 1; ret      warn: mov eax, edi; ret
        code = bytes.fromhex(
            "534883ec108d5ffc895c240c488d7c240ce816000000395c240c740abf03000000e8120000004883c4105bc3"
            "c70707000000b801000000c389f8c3"
        )
        dec = _decompile(code)
        text = dec.codegen.text
        # the comparison is not folded away, so the second call stays
        assert "sub_400038(3)" in text, text
        assert not re.search(r"\b(v\d+) [!=]= \1\b", text), text

        # helper's call defines the slot; the read after it uses that definition
        clobbered = [
            vvar
            for block in dec.clinic.cc_graph
            for stmt in block.statements
            for vvar in clobber_def_vvars(stmt)
            if vvar.was_stack
        ]
        assert [v.stack_offset for v in clobbered] == [-12]

    def test_second_call_writing_the_slot_defines_the_read(self):
        # _start(n): x = n; f(&x); g(&x); return x - n;      f: *p = 7      g: *p = 9
        code = bytes.fromhex(
            "534883ec1089fb897c240c488d7c240ce816000000488d7c240ce8130000008b44240c29d84883c4105bc3c70707000000c3"
            "c70709000000c3"
        )
        dec = _decompile(code)
        writers = {
            stmt.tags.get("ins_addr")
            for block in dec.clinic.cc_graph
            for stmt in block.statements
            if any(vvar.was_stack for vvar in clobber_def_vvars(stmt))
        }
        # g's write is the version the return reads
        assert 0x40001A in writers, writers

    def test_versions_of_an_escaped_buffer_are_one_variable(self):
        # ctf_nuclear's command loop: memset(buf), read_line(buf), strncmp(buf, ...) define and read several versions
        # of one 512-byte buffer; an address names the slot, not a version, so they print as one variable
        proj = angr.Project(os.path.join(bin_location, "tests", "i386", "ctf_nuclear"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        dec = proj.analyses.Decompiler(cfg.functions[0x8048C65], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert len(re.findall(r"char v\d+\[512\];  // \[bp-0x23c\]", text)) == 1, text

    def test_addresses_do_not_keep_a_phi_of_the_slot(self):
        # _start(n): x = n; do {} while (dec(&x)); return x;      dec(p): return --*p;
        # the loop head would merge x and dec's version for the address passed to dec alone
        code = bytes.fromhex("534883ec10897c240c488d7c240ce80e00000085c075f28b44240c4883c4105bc3ff0f8b07c3")
        dec = _decompile(code)
        stack_phis = [
            stmt
            for block in dec.clinic.cc_graph
            for stmt in block.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.was_stack
        ]
        assert not stack_phis, stack_phis
        assert re.search(r"while \(sub_400021\(&(v\d+)\)\);\s+return \1;", dec.codegen.text), dec.codegen.text

    def test_load_not_moved_across_call_after_escape(self):
        # _start(n): x = n; escape(&x); before = x; poke(); return before - x;
        #   push rbx; sub rsp, 0x10; mov [rsp+0xc], edi; lea rdi, [rsp+0xc]; call escape; mov ebx, [rsp+0xc]
        #   call poke; mov eax, ebx; sub eax, [rsp+0xc]; add rsp, 0x10; pop rbx; ret
        # escape: mov dword [rdi], 7; ret      poke: mov eax, 1; ret
        code = bytes.fromhex(
            "534883ec10897c240c488d7c240ce8150000008b5c240ce81300000089d82b44240c4883c4105bc3c70707000000c3"
            "b801000000c3"
        )
        text = _decompile(code).codegen.text
        assert not re.search(r"\b(v\d+) - \1\b", text), text

    def test_load_moved_across_call_before_escape(self):
        # _start(n): x = n; before = x; poke(); use(before); escape(&x); return x;
        # poke cannot write x yet, so `before` is still x at use()
        code = bytes.fromhex(
            "534883ec10897c240c8b5c240ce82200000089dfe821000000488d7c240ce80a0000008b44240c4883c4105bc3c707"
            "07000000c3b801000000c389f8c3"
        )
        text = _decompile(code).codegen.text
        assert re.search(r"sub_400034\(\);\s+sub_40003a\(v0\);", text), text

    def test_load_not_moved_across_call_after_escape_in_loop(self):
        # _start(n): x = n; do { before = x; poke(); use(before); } while (escape(&x)); return x;
        # from the second iteration on poke() runs after escape(&x)
        code = bytes.fromhex(
            "534883ec10897c240c8b5c240ce82800000089dfe827000000488d7c240ce80e00000085c075e28b44240c4883c410"
            "5bc3c7070700000031c0c3b801000000c389f8c3"
        )
        text = _decompile(code).codegen.text
        assert not re.search(r"sub_40003a\(\);\s+sub_400040\(v0\);", text), text


if __name__ == "__main__":
    unittest.main()
