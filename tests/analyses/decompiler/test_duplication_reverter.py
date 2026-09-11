#!/usr/bin/env python3
from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import networkx

import angr
from angr.ailment import Block
from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump, Label, Return
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import DuplicationReverter
from tests.common import bin_location, load_project_with_scoped_cfg

# sub_401d30 has a duplicate candidate below a block that ends in a call whose callee may or may not return, so the
# block has two successors without a conditional jump; listing the candidate's blocks read true_target off the call.
TRUE_BIN = os.path.join(bin_location, "tests", "x86_64", "true")
TRUE_FUNC = 0x401D30

# sub_140003a50 has a duplicate candidate whose blocks to split form a two-block loop of partial matches. Replacing
# split blocks rewires their predecessors by copying them, so with a loop one split block is always copied away before
# its own turn, and its own turn then looked it up by an identity no longer in the graph.
CANCEL_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "cancel.sys")
CANCEL_FUNC = 0x140003A50

# sub_4111a0 has two duplicated subgraphs whose starting blocks the merge
# machinery clones without splitting; the clone compares equal to the block it
# replaces, which used to make the bookkeeping re-key delete the entry it had
# just written.
GZIP_BIN = os.path.join(bin_location, "tests", "x86_64", "gzip_gcc13.3.0_O2")
GZIP_FUNC = 0x4111A0


class TestDuplicationReverter(TestCase):
    def test_a_call_that_forks_the_flow_is_an_unsupported_candidate(self):
        proj, cfg = load_project_with_scoped_cfg(TRUE_BIN, TRUE_FUNC)
        func = cfg.functions[TRUE_FUNC]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None and dec.codegen.text is not None

    def test_blocks_share_a_region_through_the_index(self):
        a, b, c = (Block(addr, 4, statements=[]) for addr in (0x1000, 0x1010, 0x1020))
        regions = [[(0x1000, None), (0x1010, None)], [(0x1010, None), (0x1020, None)]]

        class _Pass:
            class _ri:  # pylint:disable=invalid-name
                regions_by_block_addrs = regions

            _regions_by_block_loc_cache = None
            _regions_by_block_loc = DuplicationReverter._regions_by_block_loc
            _share_subregion = DuplicationReverter._share_subregion

        pass_ = _Pass()
        assert pass_._share_subregion([a, b])
        assert pass_._share_subregion([b, c])
        assert not pass_._share_subregion([a, c])
        assert not pass_._share_subregion([a, Block(0x2000, 4, statements=[])])

    def test_a_loop_of_split_blocks_is_skipped_not_raised(self):
        proj, cfg = load_project_with_scoped_cfg(CANCEL_BIN, CANCEL_FUNC)
        func = cfg.functions[CANCEL_FUNC]

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None and dec.codegen.text is not None

    def test_the_entry_block_keeps_its_address_when_a_merged_block_borrows_it(self):
        # The merged conditional block is minted with the address of the candidates' shared conditional dominator.
        # When that dominator is the function entry, two blocks carry the entry's address; renaming both left the
        # graph without an entry block, and region identification then failed to find a start node
        # (busybox setinputfile). The entry stays; the new block moves, and the jump into it follows.

        def _label(addr):
            return Label(0, f"LABEL_{addr:x}", ins_addr=addr, block_idx=None)

        entry = Block(0x1000, 8, statements=[_label(0x1000), Jump(0, Const(0, 0x1010, 64), ins_addr=0x1000)])
        mid = Block(0x1010, 8, statements=[_label(0x1010), Jump(0, Const(0, 0x1000, 64), ins_addr=0x1010)])
        merged = Block(
            0x1000,
            0,
            statements=[
                ConditionalJump(0, Const(0, 1, 1), Const(0, 0x1020, 64), Const(0, 0x1030, 64), ins_addr=0x1000),
            ],
            idx=2,
        )
        left = Block(0x1020, 4, statements=[_label(0x1020), Return(0, [], ins_addr=0x1020)])
        right = Block(0x1030, 4, statements=[_label(0x1030), Return(0, [], ins_addr=0x1030)])
        graph = networkx.DiGraph()
        for a, b in ((entry, mid), (mid, merged), (merged, left), (merged, right)):
            graph.add_edge(a, b)

        class _Minter:
            def new_block_addr(self):
                return 0x2000

        out = DuplicationReverter._uniquify_addrs(_Minter(), graph, keep={entry})

        at_entry = [n for n in out if n.addr == 0x1000]
        assert len(at_entry) == 1
        assert isinstance(at_entry[0].statements[-1], Jump)
        (moved,) = (n for n in out if n.addr == 0x2000)
        assert isinstance(moved.statements[-1], ConditionalJump)
        (new_mid,) = (n for n in out if n.addr == 0x1010)
        assert new_mid.statements[-1].target.value == 0x2000
        assert list(out.successors(new_mid)) == [moved]

    def test_merging_a_cloned_start_block_does_not_raise(self):
        # A pass that raises is not a local failure: the Decompiler catches it and
        # retries the whole function with the *basic* preset, which drops every
        # optimization pass -- so one KeyError deep inside the deduplicator
        # silently costs the function all of its decompilation quality.
        proj = angr.Project(GZIP_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(addr=GZIP_FUNC)
        assert func is not None

        dec = proj.analyses[Decompiler](func, cfg=cfg.model, preset="full")
        assert not dec.errors, [e.format() for e in dec.errors]
        assert dec.codegen is not None and dec.codegen.text is not None


if __name__ == "__main__":
    unittest.main()
