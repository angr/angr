#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.known_patterns import (
    PITE,
    CppRef,
    KnownPattern,
    PAny,
    PAnyStmt,
    PAssign,
    PatternParam,
    PBinOp,
    PBlockPat,
    PCall,
    PCallResult,
    PCallStmt,
    PChoice,
    PCondJump,
    PConst,
    PConv,
    PDefOf,
    PExtract,
    PField,
    PGraphPat,
    PLoad,
    PPhi,
    PStackField,
    PStmtSeq,
    PStore,
    PUnaryOp,
    PVVar,
)
from angr.analyses.decompiler.known_patterns.serialize import (
    NotSerializableError,
    dumps,
    known_pattern_from_dict,
    known_pattern_to_dict,
    loads,
    node_from_dict,
    node_to_dict,
)


def _every_expression_kind():
    """One tree that exercises every expression node and every field type."""
    base = PVVar(name="a0", bits=64, categories=frozenset({VirtualVariableCategory.REGISTER}))
    return PITE(
        PBinOp(frozenset({"CmpEQ", "CmpNE"}), (PLoad(PField("a0", 8, name="f"), size=4), PConst(value=0, bits=32))),
        PChoice(
            PUnaryOp("Not", PConv(PExtract(base, bits=8, offset=0), from_bits=8, to_bits=32)),
            PCall(frozenset({"strlen"}), args=(PAny(bits=64), None), name="len"),
            PCallResult(frozenset({"malloc"})),
        ),
        PDefOf(PStackField("sp", -16, as_address=True, size=8), name="d"),
    )


def _graph():
    seq = PStmtSeq(
        (
            PAssign(PVVar(name="t"), _every_expression_kind(), optional=True, weight=0.5),
            PAnyStmt(weight=2.0),
            PStore(PAny(), PPhi(bits=32), size=8),
            PCallStmt(PCall(frozenset({"free"})), dst=None),
        ),
        allow_gaps=False,
        ordered=False,
        max_gap=3,
    )
    return PGraphPat(
        blocks={"head": PBlockPat("head", seq), "tail": PBlockPat("tail", PStmtSeq((PCondJump(PAny()),)))},
        edges=[("head", "tail"), ("tail", "exit")],
        entry="head",
    )


class TestPatternSerialization(unittest.TestCase):
    def test_every_node_kind_round_trips(self):
        graph = _graph()
        assert node_from_dict(node_to_dict(graph)) == graph
        assert loads(dumps(graph)) == graph

    def test_fuzzy_fields_survive(self):
        seq = PStmtSeq((PAssign(PAny(), PAny(), optional=True, weight=0.25), PAnyStmt(optional=True)))
        back = loads(dumps(seq))
        assert back.stmts[0].optional is True
        assert back.stmts[0].weight == 0.25
        assert back.stmts[1].optional is True

    def test_operator_sets_come_back_as_frozensets(self):
        op = PBinOp(frozenset({"Add", "Sub"}), (PAny(), PAny()))
        back = loads(dumps(op))
        assert isinstance(back.op, frozenset)
        assert back == op

    def test_known_pattern_envelope_round_trips(self):
        pattern = KnownPattern(
            name="user_len",
            display_name="user::len",
            call_name="user_len",
            pattern=PStmtSeq((PAssign(PVVar(name="r"), PLoad(PVVar(name="s"), size=8)),)),
            params=(PatternParam("s", CppRef("std::string"), type_hint="std::string"), PatternParam("r", "int")),
            returnty="unsigned long",
            extra_args=("c0",),
            arches=("AMD64",),
            platforms=None,
            collapse_capture="s",
            collapse_max_capture="c0",
            default_enabled=False,
            suppressed_by=("std_vector.*", "s", "v"),
            claims_only=True,
            pure_calls=frozenset({"__ctype_b_loc"}),
        )
        back = known_pattern_from_dict(known_pattern_to_dict(pattern))
        assert back == pattern
        assert loads(dumps(pattern)) == pattern

    def test_callables_are_refused_by_name(self):
        pattern = KnownPattern(
            name="p", display_name="p", call_name="p", pattern=PAny(), params=(), where=lambda bindings: True
        )
        with self.assertRaises(NotSerializableError) as ctx:
            known_pattern_to_dict(pattern)
        assert "KnownPattern.where" in str(ctx.exception)

        with self.assertRaises(NotSerializableError) as ctx:
            node_to_dict(PConst(pred=lambda v: v > 0))
        assert "PConst.pred" in str(ctx.exception)

    def test_unknown_kind_is_rejected(self):
        with self.assertRaises(NotSerializableError):
            node_from_dict({"kind": "PNoSuchNode"})

    def test_json_is_plain(self):
        """Wire form is inspectable: node kinds are strings and nothing is pickled."""
        text = dumps(PAssign(PVVar(name="x"), PConst(value=1)), indent=1)
        assert '"kind": "PAssign"' in text
        assert '"kind": "PConst"' in text


if __name__ == "__main__":
    unittest.main()
