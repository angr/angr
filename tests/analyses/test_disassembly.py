#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
from unittest import TestCase, main

from archinfo import ArchAArch64

import angr
from angr.analyses import Disassembly
from angr.analyses.disassembly import MemoryOperand, Instruction, Value, Register
from angr.errors import AngrTypeError


class TestDisassembly(TestCase):
    def test_capstone_unsupported(self):
        # TestError because Exception is too broad
        # for the linter.
        class TestError(Exception):
            pass

        class ArchAArch64NoCapstone(ArchAArch64):
            name = "AARCH64_NOCAPSTONE"

            @property
            def capstone_support(self):
                return False

        arch = ArchAArch64NoCapstone()
        proj = angr.load_shellcode(
            b"\x00\xe4\x00\x6f"
            b"\x43\x3c\x0b\x0e"
            b"\x54\x9a\xb7\x72"
            b"\xfc\x6f\xba\xa9"
            b"\x88\x03\x98\x1a"
            b"\x00\x60\x01\x4e",
            arch,
            0,
        )
        block = proj.factory.block(0)
        expected_message = (
            f"Cannot disassemble block with architecture {arch} for block type <class 'angr.codenode.BlockNode'>"
        )
        try:
            _ = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)])
            raise TestError("We expected disassembly to fail because it didn't have capstone support")
        except AngrTypeError as error:
            # Assert failures aren't very helpful showing the difference.
            if error.args[0] != expected_message:
                raise TestError(f"\nExpected: {expected_message}\nActual:   {error.args[0]}") from error

    def test_arm64_dissect_instructions(self):
        proj = angr.load_shellcode(
            b"\x00\xe4\x00\x6f"
            b"\x43\x3c\x0b\x0e"
            b"\x54\x9a\xb7\x72"
            b"\xfc\x6f\xba\xa9"
            b"\x88\x03\x98\x1a"
            b"\x00\x60\x01\x4e",
            "AARCH64",
            0,
        )
        # movi   v0.2d, #0000000000000000'                              ; SIMD register
        # umov   w3, v2.b[5]                                            ; SIMD register index
        # movk   w20, #0xbcd2, lsl #16                                  ; ARM64 shifter
        # stp    x28, x27, [sp, #-0x60]!                                ; ARM64 pre-indexed operand
        # csel   w8, w28, w24, eq                                       ; Condition code at the end
        # tbl    v0.16b, {v0.16b, v1.16b, v2.16b, v3.16b}, v1.16b       ; Multiple SIMD regs in table
        block = proj.factory.block(0)
        disasm = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)])

        insns = [r for r in disasm.raw_result if isinstance(r, Instruction)]
        rendered_insns = [i.render()[0].lower() for i in insns]
        assert "v0.2d" in rendered_insns[0]
        assert "v2.b[5]" in rendered_insns[1]
        assert "lsl#16" in rendered_insns[2].replace(" ", "")
        assert rendered_insns[3].endswith("]!")
        assert rendered_insns[4].endswith("eq")
        insn = rendered_insns[5]
        regs_table = insn[insn.index("{") + 1 : insn.index("}")].replace(" ", "").split(",")
        assert regs_table == ["v0.16b", "v1.16b", "v2.16b", "v3.16b"]

    def test_arm32_dissect_instructions(self):
        proj = angr.load_shellcode(
            b"\x00\xc0\x2d\xe9\x10\xf9\xf9\xe9",
            "ARM",
            0,
        )
        # push    {lr, pc}
        # ldmib   sb!, {r4, r8, fp, ip, sp, lr, pc}^

        block = proj.factory.block(0)
        disasm = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)])
        insns = [r for r in disasm.raw_result if isinstance(r, Instruction)]
        rendered_insns = [i.render()[0].lower() for i in insns]
        assert all(i in rendered_insns[0] for i in ("{", "}", "lr", "pc"))
        assert "sb!" in rendered_insns[1]
        assert rendered_insns[1].endswith("^")

    def test_arm32_thumb_dissect_instructions(self):
        proj = angr.load_shellcode(b"\x00\xf9\x01\x1a", "ARM", 0, thumb=True)
        # vst1.8  {d1, d2}, [r0], r1

        block = proj.factory.block(0, thumb=True)
        disasm = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)], thumb=True)
        insns = [r for r in disasm.raw_result if isinstance(r, Instruction)]

        disassembly_operands = insns[0].operands
        capstone_operands = insns[0].insn.operands
        assert len(disassembly_operands) == len(capstone_operands)

    def test_mips32_missing_offset_in_instructions(self):
        proj = angr.load_shellcode(
            b"\x8f\xbc\x00\x10"
            b"\x02\x20\x30\x21"
            b"\x8f\x85\x80\x28"
            b"\x8f\x99\x81\x20"
            b"\x02\x40\x38\x21"
            b"\x24\xa5\x5e\x38"
            b"\x03\x20\xf8\x09"
            b"\x24\x04\x00\x02",
            "MIPS32",
            0,
        )
        # 0x0:    lw      $gp, 0x10($sp)
        # 0x4:    move    $a2, $s1
        # 0x8:    lw      $a1, -0x7fd8($gp)
        # 0xc:    lw      $t9, -0x7ee0($gp)
        # 0x10:   move    $a3, $s2
        # 0x14:   addiu   $a1, $a1, 0x5e38
        # 0x18:   jalr    $t9
        # 0x1c:   addiu   $a0, $zero, 2

        block = proj.factory.block(0)
        disass = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)])
        result = disass.raw_result
        assert len(result) == 10, f"Incorrect number of instructions ({len(result)})"

        ins = result[4]
        operand_1 = ins.operands[1]
        assert isinstance(operand_1, MemoryOperand)
        assert len(operand_1.children) == 4
        assert len(operand_1.values) == 1
        assert len(operand_1.offset) == 1
        assert operand_1.offset_location == "prefix"
        rendered = disass.render(color=False)
        assert (
            rendered
            == """   _start:
0  lw      $gp, 0x10($sp)
4  move    $a2, $s1
8  lw      $a1, -0x7fd8($gp)
c  lw      $t9, -0x7ee0($gp)
10  move    $a3, $s2
14  addiu   $a1, $a1, 0x5e38
18  jalr    $t9
1c  addiu   $a0, $zero, 0x2"""
        )

    def test_arm_data_address_display(self):
        proj = angr.load_shellcode(b"\x26\x49\x17\x48\x0b\xf0", "ARMCortexM", load_address=0x80410E6)
        # 0x80410e7:    ldr r1, [pc, #0x98]
        # 0x80410e9:    ldr r0, [pc, #0x5c]
        # 0x80410eb:    bl xxx

        block = proj.factory.block(0x80410E7)
        disass = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)])
        result = disass.raw_result

        assert len(result) == 3, f"Incorrect number of instructions ({len(result)})"
        ins0 = result[1]
        assert len(ins0.operands) == 2
        ins0op1 = ins0.operands[1]
        assert isinstance(ins0op1, MemoryOperand)
        assert len(ins0op1.values) == 1
        value = ins0op1.values[0]
        assert isinstance(value, Value)
        assert value.val == 0x8041182
        assert ins0.render()[0] == "ldr     r1, [0x8041182]"

    def test_arm_three_piece_memory_operand(self):
        proj = angr.load_shellcode(b"\xdf\xe8\x13\xf0", "ARMCortexM", load_address=0x80407F4)
        # 0x80407f4:    tbh  [pc, r3, lsl #2]

        block = proj.factory.block(0x80407F5)
        disass = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)])
        result = disass.raw_result

        assert len(result) == 2, f"Incorrect number of instructions ({len(result)})"
        ins0 = result[1]
        assert len(ins0.operands) == 1
        ins0op0 = ins0.operands[0]
        assert isinstance(ins0op0, MemoryOperand)
        assert len(ins0op0.values) == 3
        assert isinstance(ins0op0.values[0], Register)
        assert isinstance(ins0op0.values[1], Register)
        assert isinstance(ins0op0.values[2], str)
        assert ins0.render()[0] == "tbh     [pc,r3,lsl#1]"


if __name__ == "__main__":
    main()
