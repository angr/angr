# pylint:disable=missing-class-docstring,no-self-use
from unittest import TestCase, main

import angr
from angr.analyses import Disassembly
from angr.analyses.disassembly import MemoryOperand, Instruction


class TestDisassembly(TestCase):
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
        assert ["v0.16b", "v1.16b", "v2.16b", "v3.16b"] == regs_table

    def test_arm32_dissect_instructions(self):
        proj = angr.load_shellcode(
            b"\x00\xc0\x2d\xe9" b"\x10\xf9\xf9\xe9",
            "ARM",
            0,
        )
        # push {lr, pc}
        # ldmib sb!, {r4, r8, fp, ip, sp, lr, pc}^

        block = proj.factory.block(0)
        disasm = proj.analyses[Disassembly].prep()(ranges=[(block.addr, block.addr + block.size)])
        insns = [r for r in disasm.raw_result if isinstance(r, Instruction)]
        rendered_insns = [i.render()[0].lower() for i in insns]
        assert all(i in rendered_insns[0] for i in ("{", "}", "lr", "pc"))
        assert "sb!" in rendered_insns[1]
        assert rendered_insns[1].endswith("^")

    def test_mips32_missing_offset_in_instructions(self):
        proj = angr.load_shellcode(
            b"\x8f\xbc\x00\x10"
            b"\x02\x20\x30\x21"
            b"\x8F\x85\x80\x28"
            b"\x8F\x99\x81\x20"
            b"\x02\x40\x38\x21"
            b"\x24\xA5\x5E\x38"
            b"\x03\x20\xF8\x09"
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


if __name__ == "__main__":
    main()
