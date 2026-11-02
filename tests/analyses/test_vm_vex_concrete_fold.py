#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import pyvex

import angr
from angr.analyses.vm_deobfuscation.vex_concrete_fold import fold_concrete_tmps, written_image_pages


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


if __name__ == "__main__":
    unittest.main()
