# pylint:disable=missing-class-docstring,no-self-use
from unittest import TestCase, main

import angr
from angr.analyses import Disassembly
from angr.analyses.disassembly import MemoryOperand


class TestDisassembly(TestCase):
    def test_mips32_missing_offset_in_instructions(self):
        proj = angr.load_shellcode(b"\x8f\xbc\x00\x10"
                                   b"\x02\x20\x30\x21"
                                   b"\x8F\x85\x80\x28"
                                   b"\x8F\x99\x81\x20"
                                   b"\x02\x40\x38\x21"
                                   b"\x24\xA5\x5E\x38"
                                   b"\x03\x20\xF8\x09"
                                   b"\x24\x04\x00\x02",
                                   "MIPS32",
                                   0)
        # 0x0:    lw      $gp, 0x10($sp)
        # 0x4:    move    $a2, $s1
        # 0x8:    lw      $a1, -0x7fd8($gp)
        # 0xc:    lw      $t9, -0x7ee0($gp)
        # 0x10:   move    $a3, $s2
        # 0x14:   addiu   $a1, $a1, 0x5e38
        # 0x18:   jalr    $t9
        # 0x1c:   addiu   $a0, $zero, 2

        block = proj.factory.block(0)
        disass = proj.analyses[Disassembly].prep()(
            ranges=[(block.addr, block.addr + block.size)]
        )
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
        assert rendered == """   _start:
0  lw      $gp, 0x10($sp)
4  move    $a2, $s1
8  lw      $a1, -0x7fd8($gp)
c  lw      $t9, -0x7ee0($gp)
10  move    $a3, $s2
14  addiu   $a1, $a1, 0x5e38
18  jalr    $t9
1c  addiu   $a0, $zero, 0x2"""


if __name__ == "__main__":
    main()
