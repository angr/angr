# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _switch_heads(graph):
    return sorted(
        (
            block.addr,
            block.idx,
            i,
            str(stmt.switch_variable),
            [(c[0].addr if c[0] is not None else None, c[1], c[2], c[3], c[4]) for c in stmt.case_addrs],
            stmt.tags.get("ins_addr"),
            hash(stmt),
        )
        for block in graph.nodes
        for i, stmt in enumerate(block.statements)
        if isinstance(stmt, IncompleteSwitchCaseHeadStatement)
    )


class TestSwitchHeadSerialization(TestCase):
    def test_cache_with_incomplete_switch_head_round_trips(self):
        # LoweredSwitchSimplifier rewrites the if-else cascade in du's process_file into a switch head whose last
        # statement is the Python-only IncompleteSwitchCaseHeadStatement; cc_graph keeps it, so the cache must
        # serialize it.
        proj = angr.Project(os.path.join(test_location, "x86_64", "decompiler", "du.o"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(recover_variables=False, analyze_callsites=True)
        func = cfg.functions["process_file"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True, update_cache=True)
        assert dec.codegen is not None and "switch (" in dec.codegen.text
        before = _switch_heads(dec.clinic.cc_graph)
        assert before, "expected IncompleteSwitchCaseHeadStatements in cc_graph"

        blob = dec.cache.serialize()
        back = DecompilationCache.parse(blob, project=proj, kb=proj.kb, function=func, cfg=cfg.model)
        assert _switch_heads(back.clinic.cc_graph) == before
        assert back.clinic.cc_graph.number_of_nodes() == dec.clinic.cc_graph.number_of_nodes()
        assert back.clinic.cc_graph.number_of_edges() == dec.clinic.cc_graph.number_of_edges()


if __name__ == "__main__":
    main()
