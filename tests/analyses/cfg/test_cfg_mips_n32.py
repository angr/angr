#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import claripy
from angr.analyses.cfg.indirect_jump_resolvers import JumpTableResolver
from angr.analyses.cfg.indirect_jump_resolvers.jumptable import UninitReadMeta
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests", "mipsn32")


class TestCfgMipsN32(unittest.TestCase):
    """
    n32 and O64 hold a 64-bit MIPS instruction stream in an ELFCLASS32 container. Decoded as
    32-bit MIPS, a function stops at the first 64-bit instruction -- typically the `sd $gp`
    that a non-leaf prologue uses to spill the global pointer -- so almost nothing is
    recovered as code.
    """

    def _project(self, name):
        return angr.Project(os.path.join(test_location, name), auto_load_libs=False)

    def test_n32_prologue_decodes(self):
        for name in ("n32_be_static", "n32_el_dynamic", "o64_el_static"):
            proj = self._project(name)
            assert proj.arch.name == "MIPSN32", name
            sym = proj.loader.main_object.get_symbol("accumulate")
            assert sym is not None, name
            block = proj.factory.block(sym.rebased_addr)
            assert block.instructions > 1, name
            assert "sd" in {insn.mnemonic for insn in block.capstone.insns}, name

    def test_n32_cfg_covers_symbol_functions(self):
        for name in ("n32_be_static", "n32_el_dynamic", "o64_el_static"):
            proj = self._project(name)
            cfg = proj.analyses.CFGFast(normalize=True)
            covered: set[int] = set()
            for node in cfg.model.nodes():
                if node.size and isinstance(node.addr, int):
                    covered.update(range(node.addr, node.addr + node.size))
            for func_name in ("accumulate", "leaf_double", "main"):
                sym = proj.loader.main_object.get_symbol(func_name)
                assert sym is not None and sym.size, (name, func_name)
                body = set(range(sym.rebased_addr, sym.rebased_addr + sym.size))
                assert body <= covered, (name, func_name)

    def test_uninitialized_register_address_keeps_register_width(self):
        proj = self._project("n32_be_static")
        assert proj.arch.bits == 32
        resolver = JumpTableResolver(proj)
        state = proj.factory.blank_state(add_options={angr.options.REVERSE_MEMORY_NAME_MAP})
        read_addr = claripy.BVS("uninitialized_f0", 64).annotate(claripy.UninitializedAnnotation())
        state.registers.store("f0", read_addr)
        state.inspect.attrs.mem_read_address = read_addr
        state.inspect.attrs.mem_read_condition = None
        state.inspect.attrs.mem_read_length = 4

        old_base = UninitReadMeta.uninit_read_base
        try:
            resolver._init_registers_on_demand(state)  # pylint:disable=protected-access
        finally:
            UninitReadMeta.uninit_read_base = old_base

        replacement = state.inspect.attrs.mem_read_address
        assert replacement.size() == read_addr.size()
        assert state.solver.is_true(state.registers.load("f0", size=8) == replacement)


if __name__ == "__main__":
    unittest.main()
