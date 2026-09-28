#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import BinaryOp, Call, Const, Convert, Load, Register
from angr.ailment.statement import Jump
from angr.analyses.decompiler import Decompiler
from angr.analyses.decompiler.decompilation_options import get_structurer_option
from angr.analyses.decompiler.utils import switch_extract_bitwiseand_jumptable_info
from angr.sim_type import SimTypeFunction, parse_signature


class TestBoundedSwitches(unittest.TestCase):
    @staticmethod
    def _jump(index):
        bits = max(32, index.bits)
        if index.bits < bits:
            index = Convert(6, index.bits, bits, False, index)
        offset = BinaryOp(0, "Mul", [index, Const(1, 4, bits)], False, bits=bits)
        address = BinaryOp(2, "Add", [offset, Const(3, 0x400040, bits)], False, bits=bits)
        return Jump(4, Load(5, address, 4, "Iend_LE"), ins_addr=0x400008)

    @staticmethod
    def _shift(bits, amount, op="Shr"):
        value = Register(0, 8, bits)
        return BinaryOp(1, op, [value, Const(2, amount, 8)], False, bits=bits)

    def test_logical_shift_bounds(self):
        for bits, amount, upper in ((8, 7, 1), (16, 15, 1), (32, 31, 1), (64, 63, 1), (32, 22, 1023)):
            with self.subTest(bits=bits, amount=amount):
                index = self._shift(bits, amount)
                result = switch_extract_bitwiseand_jumptable_info(self._jump(index))
                assert result is not None
                assert result[0] == index
                assert result[1:] == (0, upper)

    def test_reject_unbounded_or_invalid_shifts(self):
        for amount in (-1, 0, 21, 32, 33, 255):
            with self.subTest(amount=amount):
                assert switch_extract_bitwiseand_jumptable_info(self._jump(self._shift(32, amount))) is None
        assert switch_extract_bitwiseand_jumptable_info(self._jump(self._shift(32, 31, "Sar"))) is None
        variable_shift = BinaryOp(0, "Shr", [Register(1, 8, 32), Register(2, 12, 8)], False, bits=32)
        assert switch_extract_bitwiseand_jumptable_info(self._jump(variable_shift)) is None

    def test_preserve_call_in_index(self):
        call = Call(0, Const(1, 0x400080, 32), args=[], bits=32)
        index = BinaryOp(2, "Shr", [call, Const(3, 31, 8)], False, bits=32)
        result = switch_extract_bitwiseand_jumptable_info(self._jump(index))
        assert result is not None
        assert result[0] == index
        assert result[0].operands[0] == call

    def test_unsigned_widening(self):
        index = self._shift(32, 31)
        extended = Convert(3, 32, 64, False, index)
        result = switch_extract_bitwiseand_jumptable_info(self._jump(extended))
        assert result is not None
        assert result[0] == index
        assert result[1:] == (0, 1)

    def test_reject_narrowing_and_signed_conversions(self):
        index = self._shift(32, 22)
        for converted in (Convert(3, 32, 8, False, index), Convert(4, 32, 64, True, index)):
            with self.subTest(converted=str(converted)):
                assert switch_extract_bitwiseand_jumptable_info(self._jump(converted)) is None

    def test_mask_in_either_operand(self):
        for mask in (1, 3, 1023):
            for swapped in (False, True):
                with self.subTest(mask=mask, swapped=swapped):
                    operands = [Register(0, 8, 32), Const(1, mask, 32)]
                    if swapped:
                        operands.reverse()
                    index = BinaryOp(2, "And", operands, False, bits=32)
                    result = switch_extract_bitwiseand_jumptable_info(self._jump(index))
                    assert result is not None
                    assert result[0] == index
                    assert result[1:] == (0, mask)

    def test_reject_noncontiguous_masks(self):
        for operands in ([Register(0, 8, 32), Const(1, 5, 32)], [Const(1, 5, 32), Register(0, 8, 32)]):
            index = BinaryOp(2, "And", operands, False, bits=32)
            assert switch_extract_bitwiseand_jumptable_info(self._jump(index)) is None

    def test_decompile_call_indexed_switch(self):
        for strategy in ("SAILR", "Phoenix"):
            for instruction in ("c1e81f", "83e001"):  # shr eax,31; and eax,1
                with self.subTest(strategy=strategy, instruction=instruction):
                    # A synthetic status call selects one of two distinct returns through a raw address table.
                    code = bytes.fromhex("e87b000000" + instruction + "ff248540004000b801000000c3b802000000c3")
                    code = code.ljust(0x40, b"\0") + bytes.fromhex("0f00400015004000")
                    code = code.ljust(0x80, b"\0") + bytes.fromhex("a100014000c3")
                    code = code.ljust(0x104, b"\0")
                    project = angr.load_shellcode(code, arch="x86", load_address=0x400000)
                    cfg = project.analyses.CFGFast(
                        normalize=True,
                        data_references=True,
                        regions=[(0x400000, 0x40001B), (0x400080, 0x400086)],
                    )
                    source = cfg.kb.functions[0x400080]
                    source.name = "status_source"
                    prototype = parse_signature("unsigned int status_source(void)").with_arch(project.arch)
                    assert isinstance(prototype, SimTypeFunction)
                    source.prototype = prototype
                    assert cfg.jump_tables[0x400005].jumptable_entries == [0x40000F, 0x400015]
                    result = project.analyses[Decompiler].prep(fail_fast=True)(
                        0x400000,
                        cfg=cfg.model,
                        options=[(get_structurer_option(), strategy)],
                    )
                    assert not result.structuring_failures
                    assert result.codegen is not None and result.codegen.text is not None
                    text = result.codegen.text
                    assert text.count("status_source()") == 1
                    if instruction == "c1e81f":
                        assert "status_source() >> 31" in text
                    assert text.count("switch (") == 1
                    assert "case 0:" in text and "case 1:" in text
                    assert "return 1;" in text and "return 2;" in text


if __name__ == "__main__":
    unittest.main()
