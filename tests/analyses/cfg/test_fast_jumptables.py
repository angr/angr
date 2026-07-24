#!/usr/bin/env python3
# pylint:disable=line-too-long,no-self-use,missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.cfg.indirect_jump_resolvers import (
    AMD64ElfGotResolver,
    ArmElfFastResolver,
    ConstantResolver,
    FastJumpTableResolver,
    JumpTableResolver,
    MemoryLoadResolver,
    SyscallResolver,
    X86ElfPicPltResolver,
)
from angr.knowledge_plugins.cfg import IndirectJumpType
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _jump_tables_signature(cfg):
    """A comparable (addr -> (table_addr, ordered entries)) signature of a CFG's tables."""
    return {addr: (ij.jumptable_addr, tuple(ij.jumptable_entries or [])) for addr, ij in cfg.model.jump_tables.items()}


def _callgraph_edges(cfg):
    return set(cfg.kb.functions.callgraph.edges())


# The "ALL" resolver tail, without and with the fast resolver in front of JumpTableResolver.
def _stock_chain(project, arch_specific):
    return [
        *arch_specific,
        MemoryLoadResolver(project),
        JumpTableResolver(project),
        ConstantResolver(project),
        SyscallResolver(project),
    ]


def _fast_chain(project, arch_specific):
    return [
        *arch_specific,
        MemoryLoadResolver(project),
        FastJumpTableResolver(project),
        JumpTableResolver(project),
        ConstantResolver(project),
        SyscallResolver(project),
    ]


class TestFastJumpTableResolver(unittest.TestCase):
    """
    Tests for FastJumpTableResolver: its own outputs on the shapes it handles, and A/B
    equivalence of the resolved CFG against the stock JumpTableResolver-only chain.
    """

    # (a) direct resolver outputs on absolute address tables

    def _check_direct(self, path, block_addr):
        p = angr.Project(path, auto_load_libs=False)
        cfg = p.analyses.CFGFast()  # ground truth (default chain)
        groundtruth = cfg.model.jump_tables[block_addr]

        resolver = FastJumpTableResolver(p)
        ij = cfg.indirect_jumps[block_addr]
        block = p.factory.block(block_addr)

        assert resolver.filter(cfg, block_addr, ij.func_addr, block, ij.jumpkind) is True

        ok, targets = resolver.resolve(cfg, block_addr, ij.func_addr, block, ij.jumpkind)
        assert ok is True
        assert targets is not None
        # exact, ordered match against the ground truth entries
        assert list(targets) == list(groundtruth.jumptable_entries)
        assert set(targets) == set(groundtruth.jumptable_entries)

        # the write-back onto the IndirectJump object
        written = cfg.indirect_jumps[block_addr]
        assert written.jumptable is True
        assert written.jumptable_addr == groundtruth.jumptable_addr
        assert list(written.jumptable_entries) == list(targets)
        assert written.resolved_targets == set(targets)
        assert written.type == IndirectJumpType.Jumptable_AddressLoadedFromMemory

    def test_direct_amd64_dir_gcc_O0(self):
        self._check_direct(os.path.join(test_location, "x86_64", "dir_gcc_-O0"), 0x40404C)

    def test_direct_amd64_cfgswitches(self):
        self._check_direct(os.path.join(test_location, "x86_64", "cfg_switches"), 0x4006E1)

    def test_direct_armel_cfgswitches(self):
        self._check_direct(os.path.join(test_location, "armel", "cfg_switches"), 0x10434)

    # (b) A/B equivalence of the whole CFG (fallback preserves everything the fast path skips)

    def _check_equivalence(self, path, arch_specific_cls):
        p1 = angr.Project(path, auto_load_libs=False)
        arch1 = [cls(p1) for cls in arch_specific_cls]
        stock = p1.analyses.CFGFast(indirect_jump_resolvers=_stock_chain(p1, arch1))

        p2 = angr.Project(path, auto_load_libs=False)
        arch2 = [cls(p2) for cls in arch_specific_cls]
        withfast = p2.analyses.CFGFast(indirect_jump_resolvers=_fast_chain(p2, arch2))

        assert _jump_tables_signature(stock) == _jump_tables_signature(withfast)
        assert _callgraph_edges(stock) == _callgraph_edges(withfast)

    def test_ab_amd64_dir_gcc_O0(self):
        self._check_equivalence(os.path.join(test_location, "x86_64", "dir_gcc_-O0"), [AMD64ElfGotResolver])

    def test_ab_amd64_cfgswitches(self):
        self._check_equivalence(os.path.join(test_location, "x86_64", "cfg_switches"), [AMD64ElfGotResolver])

    def test_ab_i386_cfgswitches_O0(self):
        self._check_equivalence(os.path.join(test_location, "i386", "cfg_switches_O0"), [X86ElfPicPltResolver])

    def test_ab_i386_cfgswitches_O1(self):
        self._check_equivalence(os.path.join(test_location, "i386", "cfg_switches_O1"), [X86ElfPicPltResolver])

    def test_ab_i386_cfgswitches_O2(self):
        self._check_equivalence(os.path.join(test_location, "i386", "cfg_switches_O2"), [X86ElfPicPltResolver])

    def test_ab_armel_cfgswitches(self):
        self._check_equivalence(os.path.join(test_location, "armel", "cfg_switches"), [ArmElfFastResolver])

    # (c) PIC path guard: a pre-scaled index must defer to the slow resolver (resolve_pic)

    def test_pic_prescaled_index_defers(self):
        """
        libc.so.6 block 0x5616ae has a pre-scaled index (``shl rdx,2; cmp rdx,0x4f``), so
        its true index domain is sparse ({0,4,..,76} = 20 values). Even with resolve_pic
        enabled, the fast path must bail on such a scaled bound (it would otherwise
        over-read a dense 0..79 = 80 entries); the slow JumpTableResolver recovers the
        correct 20 via VSA strided-interval cardinality.
        """
        p = angr.Project(os.path.join(test_location, "x86_64", "libc.so.6"), auto_load_libs=False)
        cfg = p.analyses.CFGFast()

        resolver = FastJumpTableResolver(p, resolve_pic=True)
        ij = cfg.indirect_jumps[0x5616AE]
        ok, targets = resolver.resolve(cfg, 0x5616AE, ij.func_addr, p.factory.block(0x5616AE), ij.jumpkind)
        assert ok is False
        assert targets is None

        # the slow resolver (in the default chain) recovered the correct sparse count
        assert 0x5616AE in cfg.model.jump_tables
        assert len(cfg.model.jump_tables[0x5616AE].jumptable_entries) == 20

    # (d) multi-block bound discovery: the bound sits 1+ blocks back / across a convergence

    def test_pic_multiblock_bound_matches_ground_truth(self):
        """
        Blocks whose bounding compare is not in the immediate single predecessor -- it is
        one or more blocks back, or split across a converging predecessor pair. The
        multi-block backward walk must recover them, and (resolve_pic=True) the recovered
        entries must exactly equal the stock chain's ground truth. 0x464719 (3-way
        convergence) and 0x4648b8 (2-pred fork) live in func 0x46c780; 0x422ae3 is a small
        2-pred fork.
        """
        p = angr.Project(os.path.join(test_location, "x86_64", "libc.so.6"), auto_load_libs=False)
        cfg = p.analyses.CFGFast()  # default chain -> stock ground truth for these PIC tables

        resolver = FastJumpTableResolver(p, resolve_pic=True)
        for block_addr in (0x422AE3, 0x464719, 0x4648B8):
            assert block_addr in cfg.model.jump_tables, f"{block_addr:#x} not resolved by stock chain"
            ground_truth = list(cfg.model.jump_tables[block_addr].jumptable_entries)

            ij = cfg.indirect_jumps[block_addr]
            ok, targets = resolver.resolve(cfg, block_addr, ij.func_addr, p.factory.block(block_addr), ij.jumpkind)
            assert ok is True, f"fast path failed to resolve {block_addr:#x}"
            assert list(targets) == ground_truth, f"entry mismatch at {block_addr:#x}"


if __name__ == "__main__":
    unittest.main()
