#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import networkx

from angr.ailment.statement import ConditionalJump, Jump, Statement
from angr.analyses.decompiler.optimization_passes.return_duplicator_low import ReturnDuplicatorLow
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


def _stmt_key(stmt: Statement) -> tuple:
    # str() leaves the target block indices out, and those are what a retargeted jump changes
    if isinstance(stmt, Jump):
        return str(stmt), stmt.target_idx
    if isinstance(stmt, ConditionalJump):
        return str(stmt), stmt.true_target_idx, stmt.false_target_idx
    return (str(stmt),)


def _snapshot(graph: networkx.DiGraph) -> tuple:
    blocks = tuple(sorted(((b.addr, b.idx), tuple(_stmt_key(s) for s in b.statements)) for b in graph.nodes))
    edges = tuple(sorted(((u.addr, u.idx), (v.addr, v.idx)) for u, v in graph.edges))
    return blocks, edges


class _InputGuardedReturnDuplicatorLow(ReturnDuplicatorLow):
    """
    ReturnDuplicatorLow that records its input graph before and after running. The pass rewrites predecessor jumps
    and region-head phis; those writes must land in its own block copies, or they survive even when the structuring
    probe rejects the result, and later passes see a graph nobody approved.
    """

    runs: list[tuple[bool, tuple, tuple]] = []

    def _analyze_and_verify(self):
        before = _snapshot(self._graph)
        super()._analyze_and_verify()
        self.runs.append((self.out_graph is None, before, _snapshot(self._graph)))


class TestReturnDuplicatorInputGraph(unittest.TestCase):
    def test_a_rejected_duplication_leaves_the_input_graph_untouched(self):
        # in xstrtoumax() the pass duplicates a return block and the structuring probe then rejects the result
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "fmt")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x406040)

        passes = DECOMPILATION_PRESETS["default"].get_optimization_passes(proj.arch, proj.simos.name)
        assert ReturnDuplicatorLow in passes
        passes = [_InputGuardedReturnDuplicatorLow if p is ReturnDuplicatorLow else p for p in passes]
        _InputGuardedReturnDuplicatorLow.runs.clear()

        dec = proj.analyses.Decompiler(
            cfg.functions[0x406040], cfg=cfg.model, optimization_passes=passes, fail_fast=True
        )
        assert dec.codegen is not None and dec.codegen.text is not None

        assert _InputGuardedReturnDuplicatorLow.runs
        assert any(rejected for rejected, _, _ in _InputGuardedReturnDuplicatorLow.runs)
        for _, before, after in _InputGuardedReturnDuplicatorLow.runs:
            assert before == after
        # the retargeted jump used to leak into the final graph and duplicate the goto in the switch
        assert dec.codegen.text.count("goto LABEL_4061d2;") == 1


if __name__ == "__main__":
    unittest.main()
