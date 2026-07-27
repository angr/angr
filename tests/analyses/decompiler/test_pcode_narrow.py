from __future__ import annotations

import archinfo

import angr


def test_decompile_8051_with_16bit_pointers():
    addr = 0x49
    arch = archinfo.ArchPcode("8051:BE:16:default")
    project = angr.load_shellcode(
        bytes.fromhex("75812b75200122"),
        arch,
        load_address=addr,
        start_offset=addr,
    )
    cfg = project.analyses.CFGFast(
        normalize=True,
        function_starts=[addr],
        regions=[(addr, addr + 7)],
        fail_fast=True,
    )

    decompiler = project.analyses.Decompiler(cfg.functions[addr], cfg=cfg.model, fail_fast=True)

    assert decompiler.codegen is not None
    assert decompiler.codegen.text is not None
    assert "g_81 = 43;" in decompiler.codegen.text
    assert "g_20 = 1;" in decompiler.codegen.text


def test_decompile_extended_avr_with_24bit_pointers():
    addr = 0x100
    arch = archinfo.ArchPcode("avr8:LE:16:extended")
    project = angr.load_shellcode(
        bytes.fromhex("01e00895"),
        arch,
        load_address=addr,
        start_offset=addr,
    )
    cfg = project.analyses.CFGFast(
        normalize=True,
        function_starts=[addr],
        regions=[(addr, addr + 4)],
        fail_fast=True,
    )

    decompiler = project.analyses.Decompiler(cfg.functions[addr], cfg=cfg.model, fail_fast=True)

    assert decompiler.codegen is not None
    assert decompiler.codegen.text is not None
    assert "g_10 = 1;" in decompiler.codegen.text
