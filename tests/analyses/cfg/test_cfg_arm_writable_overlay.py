#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import struct
import unittest

import cle

import angr

BASE = 0x60800000
EHSIZE, PHENTSIZE, SHENTSIZE = 52, 32, 40
ENTRY = BASE + 0x100  # ldr r3,=VAR; ldr r3,[r3]; ldr r2,[r3]; bl SWITCH; bx lr
SWITCH = ENTRY + 0x20  # cmp r0,#2; ldrls pc,[pc,r0,lsl #2]; b default; 3 table words; cases
LDRLS = SWITCH + 4
VAR = BASE + 0x200  # under the writable .bss, which overlays .rel.dyn (the U-Boot layout)


def _bl(src: int, dst: int) -> int:
    return 0xEB000000 | (((dst - (src + 8)) >> 2) & 0xFFFFFF)


def _b(src: int, dst: int) -> int:
    return 0xEA000000 | (((dst - (src + 8)) >> 2) & 0xFFFFFF)


def _arm_overlay_elf() -> bytes:
    """
    An ARM ET_EXEC whose writable .bss shares its bytes with an alloc section (U-Boot maps .bss over .rel.dyn).
    The file bytes under VAR hold the address of LDRLS, so folding the load chain through them puts a data
    reference in the middle of SWITCH.
    """
    cases = SWITCH + 0x18
    default = cases + 3 * 8
    code = [
        0xE59F300C,  # ldr r3, [pc, #12]
        0xE5933000,  # ldr r3, [r3]
        0xE5932000,  # ldr r2, [r3]
        _bl(ENTRY + 12, SWITCH),
        0xE12FFF1E,  # bx lr
        VAR,
        0,
        0,
        0xE3500002,  # cmp r0, #2
        0x979FF100,  # ldrls pc, [pc, r0, lsl #2]
        _b(SWITCH + 8, default),
        cases,
        cases + 8,
        cases + 16,
    ]
    for i in range(4):
        code += [0xE3A00000 | i, 0xE12FFF1E]  # mov r0, #i; bx lr
    text = b"".join(struct.pack("<I", w) for w in code)

    image = bytearray(EHSIZE + PHENTSIZE)
    image += b"\0" * (0x100 - len(image)) + text
    image += b"\0" * (0x200 - len(image)) + struct.pack("<I", LDRLS)
    image += b"\0" * (0x210 - len(image))
    load_end = len(image)

    names = b"\0.text\0.rel.dyn\0.bss\0.shstrtab\0"
    shstr_off = len(image)
    image += names + b"\0" * (-(len(image) + len(names)) % 4)
    shoff = len(image)

    def sh(name: bytes, typ: int, flags: int, addr: int, off: int, size: int, entsize: int = 0) -> bytes:
        return struct.pack("<IIIIIIIIII", names.index(name), typ, flags, addr, off, size, 0, 0, 4, entsize)

    image += bytes(SHENTSIZE)
    image += sh(b".text", 1, 0x6, ENTRY, 0x100, len(text))  # PROGBITS, AX
    image += sh(b".rel.dyn", 9, 0x2, VAR, 0x200, 0x10, 8)  # REL, A
    image += sh(b".bss", 1, 0x1, VAR, 0x200, 0x10)  # PROGBITS, W; overlays .rel.dyn
    image += sh(b".shstrtab", 3, 0, 0, shstr_off, len(names))

    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\0" * 9,
        2,  # ET_EXEC
        40,  # EM_ARM
        1,
        ENTRY,
        EHSIZE,
        shoff,
        0x05000000,  # EF_ARM_EABI_VER5
        EHSIZE,
        PHENTSIZE,
        1,
        SHENTSIZE,
        5,
        4,
    )
    load = struct.pack("<IIIIIIII", 1, 0, BASE, BASE, load_end, load_end, 7, 0x1000)
    image[: EHSIZE + PHENTSIZE] = ehdr + load
    return bytes(image)


class TestCfgArmWritableOverlay(unittest.TestCase):
    def test_writable_overlay_is_not_constant_folded(self):
        ld = cle.Loader(io.BytesIO(_arm_overlay_elf()), auto_load_libs=False)
        proj = angr.Project(ld)
        assert proj.loader.memory.unpack_word(VAR) == LDRLS
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        node = cfg.model.get_any_node(LDRLS, anyaddr=True)
        assert node is not None and node.addr == SWITCH and node.size == 8
        jt = cfg.model.jump_tables[SWITCH]
        assert jt.func_addr == SWITCH
        assert jt.jumptable_entries is not None and len(jt.jumptable_entries) == 3
        assert len(list(cfg.kb.functions[SWITCH].blocks)) == 6
        # the load of VAR itself is still a data reference
        assert VAR in {x.dst for x in cfg.kb.xrefs.get_xrefs_by_ins_addr(ENTRY + 4)}


if __name__ == "__main__":
    unittest.main()
