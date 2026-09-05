"""Decompilation of code mapped into the canonical high half of a 64-bit address
space, where kernel text lives (for example ``0xffffffff81000330`` on x86-64
Linux). Those addresses do not fit in a signed 64-bit integer."""

from __future__ import annotations

import angr
from angr.ailment.expression import Phi
from angr.ailment.statement import Assignment
from angr.analyses import Decompiler

# xor eax, eax ; test edi, edi ; je +5 ; mov eax, 1 ; ret
#
# The branch makes the recovered function span two blocks that merge on eax, so
# the decompilation carries Phi source addresses too.
SHELLCODE = bytes.fromhex("31c085ff7405b801000000c3")
LOAD_ADDR = 0xFFFFFFFF81000330


def test_decompile_amd64_at_high_canonical_address():
    project = angr.load_shellcode(SHELLCODE, "AMD64", load_address=LOAD_ADDR, start_offset=LOAD_ADDR)
    cfg = project.analyses.CFGFast(
        normalize=True,
        function_starts=[LOAD_ADDR],
        regions=[(LOAD_ADDR, LOAD_ADDR + len(SHELLCODE))],
        fail_fast=True,
    )

    function = cfg.functions[LOAD_ADDR]
    decompiler = project.analyses[Decompiler].prep(fail_fast=True)(function, cfg=cfg.model)

    assert decompiler.codegen is not None
    assert decompiler.codegen.text is not None
    assert "return" in decompiler.codegen.text

    assert decompiler.ail_graph is not None
    block_addrs = {block.addr for block in decompiler.ail_graph}
    assert all(LOAD_ADDR <= block_addr < LOAD_ADDR + len(SHELLCODE) for block_addr in block_addrs)

    # The two branch arms merge on eax, so the merge block holds a phi whose
    # sources are the addresses of the blocks it merges.
    phi_src_addrs = {
        src_addr
        for block in decompiler.ail_graph
        for stmt in block.statements
        if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)
        for (src_addr, _), _ in stmt.src.src_and_vvars
    }
    assert phi_src_addrs
    assert all(LOAD_ADDR <= src_addr < LOAD_ADDR + len(SHELLCODE) for src_addr in phi_src_addrs)
