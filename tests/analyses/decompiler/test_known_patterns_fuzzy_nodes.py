#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import unittest

from angr.ailment.expression import Const, Convert, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.known_patterns import (
    KnownPattern,
    KnownPatternFinder,
    PAny,
    PAnyStmt,
    PAssign,
    PBlockPat,
    PCondJump,
    PConst,
    PGraphPat,
    PStmtSeq,
    PStore,
    PVVar,
    has_fuzzy_nodes,
    iter_stmt_patterns,
)
from angr.analyses.decompiler.known_patterns.dsl import MatchCtx, MatchState, stmt_pattern_anchor_key


def _vvar(manager, varid, bits=32):
    return VirtualVariable(manager.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=16)


def _pattern(node):
    return KnownPattern(name="p", display_name="p", call_name="p", pattern=node, params=())


class TestFuzzyStatementNodes(unittest.TestCase):
    """The three additions the fuzzy matcher needs from the DSL."""

    def test_any_statement_matches_every_statement_kind(self):
        manager = Manager()
        assign = Assignment(manager.next_atom(), _vvar(manager, 1), Const(manager.next_atom(), 7, 32))
        store = Store(manager.next_atom(), _vvar(manager, 2), Const(manager.next_atom(), 7, 32), 4, "Iend_LE")

        for stmt in (assign, store):
            assert PAnyStmt().match(stmt, MatchState(), MatchCtx()) is not None

    def test_fuzzy_fields_default_off_and_do_not_disturb_positional_construction(self):
        assign = PAssign(PAny(), PAny())
        assert assign.optional is False
        assert assign.weight == 1.0

        store = PStore(PAny(), PAny(), 4, optional=True, weight=0.5)
        assert store.size == 4
        assert store.optional is True
        assert store.weight == 0.5

    def test_fuzzy_fields_must_be_passed_by_keyword(self):
        with self.assertRaises(TypeError):
            PCondJump(PAny(), True)  # pylint:disable=too-many-function-args

    def test_leaf_walker_reaches_into_sequences_and_graphs(self):
        seq = PStmtSeq((PAssign(PAny(), PAny()), PAnyStmt(), PStore(PAny(), PAny())))
        graph = PGraphPat(
            blocks={"a": PBlockPat("a", seq), "b": PBlockPat("b", PStmtSeq((PCondJump(PAny()),)))},
            edges=[("a", "b"), ("b", "out")],
            entry="a",
        )

        kinds = [type(s).__name__ for s in iter_stmt_patterns(graph)]
        assert kinds == ["PAssign", "PAnyStmt", "PStore", "PCondJump"]

    def test_only_an_optional_statement_makes_a_pattern_fuzzy(self):
        exact = PStmtSeq((PAssign(PAny(), PAny()), PAnyStmt(weight=3.0)))
        fuzzy = PStmtSeq((PAssign(PAny(), PAny()), PAnyStmt(optional=True)))

        assert not has_fuzzy_nodes(exact), "a wildcard statement and a weight are fine for the exact matcher"
        assert has_fuzzy_nodes(fuzzy)

    def test_exact_finder_leaves_fuzzy_patterns_out_and_says_so(self):
        exact = _pattern(PStmtSeq((PAssign(PAny(), PAny()),)))
        fuzzy = _pattern(PStmtSeq((PAssign(PAny(), PAny(), optional=True),)))

        with self.assertLogs("angr.analyses.decompiler.known_patterns.finder", level=logging.WARNING) as logs:
            kept = KnownPatternFinder._drop_fuzzy_patterns([exact, fuzzy])

        assert kept == [exact]
        assert "optional statements" in logs.output[0]

    def test_leaves_step_over_conversions_only_when_asked(self):
        manager = Manager()
        wrapped = Convert(manager.next_atom(), 32, 64, True, _vvar(manager, 1))
        assert PVVar().match(wrapped, MatchState(), MatchCtx()) is None, "the exact library spells conversions out"
        state = PVVar(name="x").match(wrapped, MatchState(), MatchCtx(skip_conversions_at_leaves=True))
        assert state is not None
        assert isinstance(state.bindings["x"], VirtualVariable)
        assert PConst(value=5).match(
            Convert(manager.next_atom(), 8, 32, False, Const(manager.next_atom(), 5, 8)),
            MatchState(),
            MatchCtx(skip_conversions_at_leaves=True),
        )

    def test_a_named_wildcard_binds_what_a_variable_would(self):
        """cut_depth turns a deep named variable into a named wildcard; it must bind the same
        thing the variable binds elsewhere, or the two uses can never unify."""
        manager = Manager()
        var = _vvar(manager, 1)
        wrapped = Convert(manager.next_atom(), 32, 64, True, var)
        ctx = MatchCtx(skip_conversions_at_leaves=True)
        state = PVVar(name="x").match(var, MatchState(), ctx)
        assert state is not None
        assert PAny(name="x").match(wrapped, state, ctx) is not None

    def test_a_sequence_led_by_a_wildcard_statement_is_tried_everywhere(self):
        assert stmt_pattern_anchor_key(PStmtSeq((PAnyStmt(), PAssign(PAny(), PAny())))) is None


if __name__ == "__main__":
    unittest.main()
