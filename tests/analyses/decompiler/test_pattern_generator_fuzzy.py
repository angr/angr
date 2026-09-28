#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.known_patterns import (
    PAny,
    PCallStmt,
    PConst,
    PGraphPat,
    PLoad,
    PReturn,
    PStmtSeq,
    iter_stmt_patterns,
)
from angr.analyses.decompiler.known_patterns.generator import PatternGenerationError, PatternGenerator
from angr.analyses.fuzzy_patterns.search import find_template_occurrences
from tests.common import bin_location

BIN_PATH = os.path.join(bin_location, "tests")


class TestGenerateFuzzy(unittest.TestCase):
    """Text span in, fuzzy pattern out, with nothing else asked of the user."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        func = proj.kb.functions["doit"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.ail_graph is not None and dec.codegen is not None
        cls.dec = dec
        cls.func = func
        cls.kb = proj.kb
        cls.gen = PatternGenerator(dec.codegen, dec.ail_graph)

    def _adjacent_pair(self):
        """The text span of two assignment statements of one block, by their chunks' instruction
        addresses. Whatever else lies in the span joins the selection."""
        cg = self.dec.codegen
        chunks: dict[int, list[tuple[int, int]]] = {}
        for pos, elem in cg.map_pos_to_node.items():
            ins = (getattr(elem.obj, "tags", None) or {}).get("ins_addr")
            if ins is not None:
                chunks.setdefault(ins, []).append((pos, pos + elem.length))
        for block in self.dec.ail_graph:
            addrs = []
            for stmt in block.statements:
                ins = stmt.tags.get("ins_addr")
                if isinstance(stmt, (Assignment, Store)) and ins in chunks and ins not in addrs:
                    addrs.append(ins)
            if len(addrs) >= 2:
                spans = chunks[addrs[0]] + chunks[addrs[1]]
                return min(s for s, _ in spans), max(e for _, e in spans)
        raise AssertionError("no block renders two assignment statements")

    def test_two_adjacent_statements_become_a_sequence(self):
        start, end = self._adjacent_pair()
        pattern = self.gen.generate_fuzzy(start, end, "my_idiom")

        assert isinstance(pattern.pattern, (PStmtSeq, PGraphPat))
        assert len(list(iter_stmt_patterns(pattern.pattern))) >= 2
        assert pattern.call_name == "my_idiom"
        assert pattern.name == "my_idiom"
        assert [p.capture for p in pattern.params] == [f"a{i}" for i in range(len(pattern.params))]

    def test_the_selection_finds_itself_verified(self):
        start, end = self._adjacent_pair()
        pattern = self.gen.generate_fuzzy(start, end, "my_idiom")
        entry = next(b for b in self.dec.ail_graph if b.addr == self.func.addr)

        _stream, matches = find_template_occurrences(pattern, self.dec.ail_graph, entry, kb=self.kb)
        assert any(m.similarity == 1.0 and m.verified for m in matches), "the source of the pattern must match it"

    def test_puts_fflush_return_lifts_to_two_calls_and_a_return(self):
        """The error-exit idiom of doit: the string argument and the inputs are wildcards, the
        global stream pointer and the returned constant are kept, and nothing becomes a parameter."""
        m = re.search(r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n', self.gen.text)
        assert m is not None
        pattern = self.gen.generate_fuzzy(m.start(), m.end(), "PatternErrorsOut")

        assert isinstance(pattern.pattern, PStmtSeq)
        puts, fflush, ret = pattern.pattern.stmts
        assert isinstance(puts, PCallStmt) and puts.call.names == {"puts"} and puts.call.args == (PAny(name="_s1"),)
        assert isinstance(fflush, PCallStmt) and fflush.call.names == {"fflush"}
        (stdout,) = fflush.call.args
        assert isinstance(stdout, PLoad) and isinstance(stdout.addr, PConst) and stdout.addr.value is not None
        assert isinstance(ret, PReturn) and ret.values == (PConst(value=0xFFFFFFFF),)
        assert pattern.params == ()

        entry = next(b for b in self.dec.ail_graph if b.addr == self.func.addr)
        _, matches = find_template_occurrences(pattern, self.dec.ail_graph, entry, kb=self.kb)
        verified = [m for m in matches if m.verified]
        assert len(verified) >= 8, "every error exit of doit spells the idiom"

    def test_the_whole_function_lifts_calls_and_returns(self):
        """A span over the whole function covers calls and returns, which have patterns of their own."""
        pattern = self.gen.generate_fuzzy(0, len(self.gen.text), "whole")
        leaves = list(iter_stmt_patterns(pattern.pattern))
        assert any(isinstance(leaf, PCallStmt) for leaf in leaves)
        assert any(isinstance(leaf, PReturn) for leaf in leaves)
        assert isinstance(pattern.pattern, PStmtSeq)
        assert len(leaves) > 20, "the whole function is in there"

    def test_empty_and_expression_only_selections_are_refused(self):
        with self.assertRaises(PatternGenerationError):
            self.gen.generate_fuzzy(10, 10, "x")
        # a single character cannot cover a whole statement
        with self.assertRaises(PatternGenerationError):
            self.gen.generate_fuzzy(0, 1, "x")


if __name__ == "__main__":
    unittest.main()
