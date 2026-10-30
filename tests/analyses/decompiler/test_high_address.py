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

# Relocate the tracked PIE to the conventional x86-64 Linux kernel base.
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

    # The loop's induction-variable phi also exercises source-block addresses.
    phi_src_addrs = set()
    for block in decompiler.ail_graph:
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                sources = stmt.src.src_and_vvars or ()
                phi_src_addrs.update(source[0] for source, _ in sources if source is not None)
    assert phi_src_addrs
    assert all(addr > 0x7FFFFFFFFFFFFFFF for addr in phi_src_addrs)
