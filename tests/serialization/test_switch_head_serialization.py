# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement
from angr.utils.ail_serialization import pack_graph, parse_graph
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _heads(graph):
    return [
        (block, i, stmt)
        for block in graph.nodes
        for i, stmt in enumerate(block.statements)
        if isinstance(stmt, IncompleteSwitchCaseHeadStatement)
    ]


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


class TestSwitchHeadLabelWidth(TestCase):
    """A case label is the unsigned value of the comparison constant, so it does not always fit an int64."""

    @staticmethod
    def _chunker_switch_head():
        # sub_40ae4e switches on a 64-bit variable and compares it with -2, which reaches the switch head as
        # 0xfffffffffffffffe.
        path = os.path.join(test_location, "riscv", "borgbackup2-chunker.cpython-312-riscv64-linux-gnu.so")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)
        func = cfg.functions[0x40AE4E]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, update_cache=True)
        clinic = dec.clinic
        assert clinic is not None
        graph = clinic.cc_graph
        assert graph is not None
        return proj, cfg, func, clinic, graph

    def test_the_switch_head_labels_a_case_above_int64_max(self):
        # Guards the fixture itself: without this the round-trip tests would keep passing once the label stopped
        # being produced, while testing nothing.
        *_rest, graph = self._chunker_switch_head()
        heads = _heads(graph)
        assert len(heads) == 1, f"expected one switch head, got {len(heads)}"
        _block, _i, stmt = heads[0]
        assert stmt.switch_variable.bits == 64
        labels = [value for _, value, _, _, _ in stmt.case_addrs if not isinstance(value, str)]
        assert any(value >= 2**63 for value in labels), labels

    def test_clinic_with_a_label_above_int64_max_round_trips(self):
        # The clinic on its own, which is the serializer this change touches; the whole DecompilationCache
        # round-trips too, and TestSwitchHeadSerialization covers that shape for a label that fits.
        proj, cfg, func, clinic, graph = self._chunker_switch_head()
        before = _switch_heads(graph)
        assert before

        blob = clinic.serialize()
        back = Clinic.parse(blob, project=proj, kb=proj.kb, function=func, cfg=cfg.model)
        back_graph = back.cc_graph
        assert back_graph is not None
        assert _switch_heads(back_graph) == before
        assert back_graph.number_of_nodes() == graph.number_of_nodes()
        assert back_graph.number_of_edges() == graph.number_of_edges()

    def test_a_label_of_every_width_round_trips(self):
        # uint_value plus value_signed carries the whole of [-2**63, 2**64) with no value representable twice,
        # so every label the simplifier can record round-trips. Substituting the label on the real graph keeps
        # the rest of the statement exactly as the decompiler built it.
        *_rest, graph = self._chunker_switch_head()
        _block, _i, stmt = _heads(graph)[0]
        original = list(stmt.case_addrs)
        try:
            for value in (-(2**63), -2, 0, 1, 2**63 - 1, 2**63, 2**64 - 1):
                stmt.case_addrs = [
                    case if isinstance(case[1], str) else (case[0], value, case[2], case[3], case[4])
                    for case in original
                ]
                msg = pack_graph(graph)
                back = parse_graph(type(msg).FromString(msg.SerializeToString()))
                labels = {
                    case[1]
                    for _block, _i, parsed in _heads(back)
                    for case in parsed.case_addrs
                    if not isinstance(case[1], str)
                }
                assert labels == {value}, f"label {value} came back as {labels}"
        finally:
            stmt.case_addrs = original


if __name__ == "__main__":
    main()
