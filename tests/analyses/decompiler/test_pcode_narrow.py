from __future__ import annotations

import archinfo

import angr
from angr.analyses.decompiler import Decompiler


def _decompile_shellcode(langid: str, code: bytes, addr: int) -> Decompiler:
    arch = archinfo.ArchPcode(langid)
    project = angr.load_shellcode(
        code,
        arch,
        load_address=addr,
        start_offset=addr,
        # the default rebase granularity is larger than a 16-bit address space, so ask for one that fits and let the
        # extern object pack in behind the shellcode
        rebase_granularity=0x100,
    )
    cfg = project.analyses.CFGFast(
        normalize=True,
        function_starts=[addr],
        regions=[(addr, addr + len(code))],
        fail_fast=True,
    )
    return project.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[addr], cfg=cfg.model)


def test_decompile_z80_with_16bit_pointers():
    # Z80 addresses are 16 bits wide. Typehoon's SimpleSolver only had lattices for 32- and 64-bit pointers and
    # rejected the whole function with "Pointer size 16 is not supported".
    decompiler = _decompile_shellcode(
        "z80:LE:16:default",
        # ld a, 1 / ld (0x1234), a / ret
        bytes.fromhex("3e01323412c9"),
        0x100,
    )

    assert decompiler.codegen is not None
    assert decompiler.codegen.text is not None
    assert "g_1234 = 1;" in decompiler.codegen.text


def test_decompile_extended_avr_with_24bit_pointers():
    # Extended AVR8 addresses are 24 bits wide, which is not a pyvex constant width; the p-code lifter used to raise
    # KeyError while building the block's jump target, before typehoon ever saw the function.
    decompiler = _decompile_shellcode(
        "avr8:LE:16:extended",
        # ldi r16, 1 / ret
        bytes.fromhex("01e00895"),
        0x100,
    )

    assert decompiler.codegen is not None
    assert decompiler.codegen.text is not None
    assert "g_10 = 1;" in decompiler.codegen.text
