from __future__ import annotations

import angr


def test_decompile_amd64_at_high_canonical_address():
    addr = 0xFFFFFFFF81000330
    project = angr.load_shellcode(bytes.fromhex("31c0c3"), "AMD64", load_address=addr, start_offset=addr)
    cfg = project.analyses.CFGFast(
        normalize=True,
        function_starts=[addr],
        regions=[(addr, addr + 3)],
        fail_fast=True,
    )

    decompiler = project.analyses.Decompiler(cfg.functions[addr], cfg=cfg.model, fail_fast=True)

    assert decompiler.codegen is not None
    assert decompiler.codegen.text is not None
    assert "return 0;" in decompiler.codegen.text
