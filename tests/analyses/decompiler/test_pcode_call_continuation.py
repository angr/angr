# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

import angr
from angr import ailment
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestPcodeCallContinuation(unittest.TestCase):
    """
    In sparc64/calls, tail_in_branch makes a `call; restore` tail call, an ordinary call and a second tail call, in
    that order.
    """

    def _load(self):
        proj = angr.Project(os.path.join(test_location, "sparc64", "calls"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions["tail_in_branch"]
        call_blocks = sorted((b for b in func.blocks if b.vex.jumpkind == "Ijk_Call"), key=lambda b: b.addr)
        return proj, cfg, func, call_blocks

    def test_converted_block_ends_at_its_call(self):
        _, _, _, call_blocks = self._load()
        returns_after_call = []
        for block in call_blocks:
            last_stmt = ailment.IRSBConverter.convert(block.vex, ailment.Manager()).statements[-1]
            assert isinstance(last_stmt, ailment.Stmt.SideEffectStatement)
            returns_after_call.append(bool(last_stmt.tags.get("returns_after_call")))
        assert returns_after_call == [True, False, True]

    def test_tail_call_returns(self):
        proj, cfg, func, call_blocks = self._load()
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.clinic is not None
        graph = dec.clinic.graph
        assert graph is not None
        nodes = {node.addr: node for node in graph}
        tail_call, ordinary_call, last_tail_call = call_blocks

        # each tail call returns: the first one does not fall through into the ordinary call right after it
        for block in (tail_call, last_tail_call):
            (succ,) = graph.successors(nodes[block.addr])
            assert isinstance(succ.statements[-1], ailment.Stmt.Return)
            assert graph.out_degree[succ] == 0
        assert [succ.addr for succ in graph.successors(nodes[ordinary_call.addr])] == [last_tail_call.addr]


if __name__ == "__main__":
    unittest.main()
