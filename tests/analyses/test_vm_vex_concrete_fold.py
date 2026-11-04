#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import pyvex

import angr
from angr import claripy
from angr.analyses.vm_deobfuscation.vex_concrete_fold import (
    fold_concrete_tmps,
    symbolize_uninitialized_data,
    uninitialized_data_ranges,
    written_image_pages,
)

from tests.common import bin_location


def _const_of_tmp_loaded_into(irsb, reg_name):
    """The constant a folded block puts into `reg_name`, or None."""
    offset = irsb.arch.registers[reg_name][0]
    defs = {s.tmp: s.data for s in irsb.statements if isinstance(s, pyvex.stmt.WrTmp)}
    for stmt in irsb.statements:
        if isinstance(stmt, pyvex.stmt.Put) and stmt.offset == offset and isinstance(stmt.data, pyvex.expr.RdTmp):
            data = defs.get(stmt.data.tmp)
            while isinstance(data, pyvex.expr.Unop) and isinstance(data.args[0], pyvex.expr.RdTmp):
                data = defs.get(data.args[0].tmp)
            if isinstance(data, pyvex.expr.Const):
                return data.con.value
    return None


class TestVexConcreteFold(unittest.TestCase):
    @staticmethod
    def _fold(code: bytes, volatile_pages=(), size=None):
        proj = angr.load_shellcode(code, arch="amd64")
        irsb = proj.factory.block(0, size or len(code), opt_level=0).vex
        return irsb, fold_concrete_tmps(proj, irsb, volatile_pages)

    def test_folds_a_value_computed_through_the_stack(self):
        # a VMProtect NOR on a stack slot: whatever rdi is, eax = ~0x1234
        irsb, folded = self._fold(
            bytes.fromhex(
                "48897c24f8"  # mov [rsp-8], rdi
                "c74424f834120000"  # mov dword [rsp-8], 0x1234
                "f75424f8"  # not dword [rsp-8]
                "8b4424f8"  # mov eax, [rsp-8]
                "c3"
            )
        )
        assert folded is not None
        assert _const_of_tmp_loaded_into(folded, "rax") == 0xFFFFEDCB
        assert len(folded.statements) == len(irsb.statements)

    def test_keeps_inputs_and_stack_addresses_symbolic(self):
        irsb, folded = self._fold(
            bytes.fromhex(
                "4889e0"  # mov rax, rsp
                "4801f8"  # add rax, rdi
                "c3"
            )
        )
        assert folded is None or _const_of_tmp_loaded_into(folded, "rax") is None

    def test_a_pointer_write_does_not_reach_a_stack_slot(self):
        _, folded = self._fold(
            bytes.fromhex(
                "c74424f807000000"  # mov dword [rsp-8], 7
                "c70705000000"  # mov dword [rdi], 5
                "8b4424f8"  # mov eax, [rsp-8]
                "8b0f"  # mov ecx, [rdi]
                "c3"
            )
        )
        assert folded is not None
        assert _const_of_tmp_loaded_into(folded, "rax") == 7
        assert _const_of_tmp_loaded_into(folded, "rcx") is None

    def test_an_image_page_another_block_writes_is_not_constant(self):
        reader = bytes.fromhex("8b042540000000c3").ljust(0x48, b"\x00")  # mov eax, [0x40]; ret
        reader = reader[:0x40] + (0x11223344).to_bytes(4, "little") + reader[0x44:]
        _, folded = self._fold(reader, size=8)
        assert folded is not None and _const_of_tmp_loaded_into(folded, "rax") == 0x11223344
        writer = bytes.fromhex("c7042540000000" "01000000" "c3").ljust(0x48, b"\x00")  # mov dword [0x40], 1; ret
        proj = angr.load_shellcode(writer, arch="amd64")
        assert written_image_pages(proj, [proj.factory.block(0, 11, opt_level=0).vex]) == {0}
        _, folded = self._fold(reader, volatile_pages={0}, size=8)
        assert folded is None or _const_of_tmp_loaded_into(folded, "rax") is None

    def test_flags_at_block_entry_are_unknown(self):
        # blank_state seeds cc_op and the direction flag; a block entered from anywhere knows neither
        _, folded = self._fold(bytes.fromhex("9c" "58" "2500040000" "c3"))  # pushfq; pop rax; and eax, 0x400; ret
        assert folded is None or _const_of_tmp_loaded_into(folded, "rax") is None

    def test_a_block_that_reads_the_entry_flags_is_folded(self):
        # pushfq at a VM entry saves the native flags; the rest of the block still folds
        _, folded = self._fold(bytes.fromhex("9c" "b805000000" "c3"))  # pushfq; mov eax, 5; ret
        assert folded is not None and _const_of_tmp_loaded_into(folded, "rax") == 5

    def test_the_entry_cc_op_is_not_a_constant(self):
        irsb, folded = self._fold(bytes.fromhex("9c" "b805000000" "c3"))
        cc_op = irsb.arch.registers["cc_op"][0]
        for old, new in zip(irsb.statements, folded.statements):
            if isinstance(old, pyvex.stmt.WrTmp) and isinstance(old.data, pyvex.expr.Get) and old.data.offset == cc_op:
                assert not isinstance(new.data, pyvex.expr.Const)

    def test_a_block_that_reads_the_entry_flags_has_known_writes(self):
        code = bytes.fromhex("9c" "c7042540000000" "01000000" "c3").ljust(0x1100, b"\x00")  # pushfq; mov [0x40], 1
        proj = angr.load_shellcode(code, arch="amd64")
        assert written_image_pages(proj, [proj.factory.block(0, 13, opt_level=0).vex]) == {0}


class TestUninitializedData(unittest.TestCase):
    """A global with no file contents is zero only at load time; reading it gives no constant."""

    @staticmethod
    def _guard_on_global(addr: int) -> bytes:
        # movabs rax, [addr]; cmp rax, 0; setne cl; ret
        return b"\x48\xa1" + addr.to_bytes(8, "little") + bytes.fromhex("4883f800" "0f95c1" "c3")

    def _check(self, path, expected):
        proj = angr.Project(path, auto_load_libs=False)
        assert uninitialized_data_ranges(proj) == expected
        addr = expected[0][0]
        code = self._guard_on_global(addr)
        irsb = proj.factory.block(0x1000, byte_string=code, opt_level=0).vex
        folded = fold_concrete_tmps(proj, irsb)
        assert folded is None or _const_of_tmp_loaded_into(folded, "rax") is None
        state = proj.factory.blank_state()
        symbolize_uninitialized_data(state, proj)
        first = state.memory.load(addr, 8)
        assert first.symbolic
        # the same unknown on every read and in every copy; a write replaces it
        copy = state.copy()
        assert copy.memory.load(addr, 8) is first or copy.memory.load(addr, 8).structurally_match(first)
        copy.memory.store(addr, claripy.BVV(7, 64))
        assert copy.solver.eval_one(copy.memory.load(addr, 8)) == 7
        assert state.memory.load(addr, 8).symbolic
        # a partial write to an untouched word leaves its other bytes unknown
        word = addr + 8 if expected[0][1] >= 16 else addr
        state.memory.store(word, claripy.BVV(1, 8))
        value = state.memory.load(word, 8)
        assert value.symbolic and state.solver.eval_one(value[63:56]) == 1
        # inside byte_code_regions the image bytes are kept
        proj.byte_code_regions = [(addr, addr + 1)]
        assert uninitialized_data_ranges(proj) == []

    def test_elf_bss(self):
        self._check(os.path.join(bin_location, "tests", "x86_64", "fauxware"), [(0x601050, 0x10)])

    def test_pe_data_tail(self):
        # .data: 0x400 bytes of file contents, 0xa19 in memory
        self._check(
            os.path.join(bin_location, "tests", "x86_64", "windows", "fauxware.exe"), [(0x14000C400, 0x619)]
        )


if __name__ == "__main__":
    unittest.main()
