"""Decompilation of code mapped into the canonical high half of a 64-bit address
space, where kernel text lives (for example ``0xffffffff81000330`` on x86-64
Linux). Those addresses do not fit in a signed 64-bit integer."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os

import angr
from angr.ailment.expression import Phi
from angr.ailment.statement import Assignment
from angr.analyses import Decompiler
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# Kernel text on x86-64 Linux starts at 0xffffffff81000000. Mapping an ordinary
# position-independent executable there puts its code at the same addresses
# without needing a kernel image as a fixture.
LOAD_ADDR = 0xFFFFFFFF81000000


def test_decompile_amd64_at_high_canonical_address():
    project = angr.Project(
        os.path.join(test_location, "x86_64", "decompiler", "loop"),
        auto_load_libs=False,
        main_opts={"base_addr": LOAD_ADDR},
    )
    cfg = project.analyses.CFGFast(normalize=True, fail_fast=True)

    function = cfg.functions.function(name="loop")
    assert function is not None
    assert function.addr > 0x7FFFFFFFFFFFFFFF

    decompiler = project.analyses[Decompiler].prep(fail_fast=True)(function, cfg=cfg.model)

    assert decompiler.codegen is not None
    assert decompiler.codegen.text is not None
    assert "return" in decompiler.codegen.text

    assert decompiler.ail_graph is not None
    block_addrs = {block.addr for block in decompiler.ail_graph}
    assert block_addrs
    assert all(addr > 0x7FFFFFFFFFFFFFFF for addr in block_addrs)

    # The loop's back edge merges on the induction variable, so the header block
    # holds a phi whose sources are the addresses of the blocks it merges.
    phi_src_addrs = {
        src_addr
        for block in decompiler.ail_graph
        for stmt in block.statements
        if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)
        for (src_addr, _), _ in stmt.src.src_and_vvars
    }
    assert phi_src_addrs
    assert all(addr > 0x7FFFFFFFFFFFFFFF for addr in phi_src_addrs)
