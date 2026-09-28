#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.analyses.decompiler.known_patterns import (
    KnownPattern,
    PAny,
    PAnyStmt,
    PAssign,
    PatternParam,
    PBinOp,
    PBlockPat,
    PChoice,
    PConst,
    PGraphPat,
    PLoad,
    PStmtSeq,
    PStore,
    PVVar,
)
from angr.analyses.decompiler.known_patterns.edit import PatternEditor, describe


def _pattern():
    seq = PStmtSeq(
        (
            PAssign(PVVar(name="t"), PBinOp("Add", (PVVar(name="a0"), PConst(value=8)))),
            PStore(PVVar(name="a1"), PLoad(PVVar(name="t"), size=8), size=8),
            PAssign(PVVar(name="r"), PChoice(PConst(value=1), PConst(value=2))),
        )
    )
    return KnownPattern(
        name="p", display_name="p", call_name="p", pattern=seq, params=(PatternParam("a0"), PatternParam("a1"))
    )


class TestNavigation(unittest.TestCase):
    def test_leaves_with_paths(self):
        ed = PatternEditor(_pattern())
        leaves = ed.leaves()
        assert [path for path, _ in leaves] == [("stmts", 0), ("stmts", 1), ("stmts", 2)]
        assert [PatternEditor.leaf_mode(leaf) for _, leaf in leaves] == ["required"] * 3

    def test_children_follow_fields_and_tuples(self):
        ed = PatternEditor(_pattern())
        kids = ed.children(("stmts", 0))
        assert [p for p, _ in kids] == [("stmts", 0, "dst"), ("stmts", 0, "src")]
        ops = ed.children(("stmts", 0, "src"))
        assert [p for p, _ in ops] == [("stmts", 0, "src", "operands", 0), ("stmts", 0, "src", "operands", 1)]
        assert isinstance(ed.node_at(("stmts", 0, "src", "operands", 1)), PConst)

    def test_graph_blocks_are_children_in_matcher_order(self):
        a = PBlockPat("a", PStmtSeq((PAssign(PAny(), PConst(value=1)),)))
        b = PBlockPat("b", PStmtSeq((PAssign(PAny(), PConst(value=2)),)))
        c = PBlockPat("c", PStmtSeq((PAssign(PAny(), PConst(value=3)),)))
        graph = PGraphPat(blocks={"a": a, "b": b, "c": c}, edges=[("a", "c"), ("c", "b"), ("b", "out")], entry="a")
        ed = PatternEditor(KnownPattern(name="g", display_name="g", call_name="g", pattern=graph, params=()))

        assert [p for p, _ in ed.children(())] == [("a",), ("c",), ("b",)]
        assert [leaf.src.value for _, leaf in ed.leaves()] == [1, 3, 2]


class TestEdits(unittest.TestCase):
    def test_leaf_modes_and_undo(self):
        ed = PatternEditor(_pattern())
        ed.set_leaf_mode(("stmts", 1), "optional")
        assert ed.node_at(("stmts", 1)).optional is True

        ed.set_leaf_mode(("stmts", 1), "wildcard")
        leaf = ed.node_at(("stmts", 1))
        assert isinstance(leaf, PAnyStmt)
        assert leaf.optional is True, "wildcarding keeps optionality"

        assert ed.undo()
        assert isinstance(ed.node_at(("stmts", 1)), PStore), "undo brings the shape back"
        assert ed.undo()
        assert ed.node_at(("stmts", 1)).optional is False
        assert not ed.undo()

    def test_weight(self):
        ed = PatternEditor(_pattern())
        ed.set_leaf_weight(("stmts", 0), 3)
        assert ed.node_at(("stmts", 0)).weight == 3.0

    def test_expression_wildcard_keeps_the_capture(self):
        ed = PatternEditor(_pattern())
        ed.set_expr_wildcard(("stmts", 0, "src"))
        assert ed.node_at(("stmts", 0, "src")) == PAny()
        ed.set_expr_wildcard(("stmts", 0, "dst"))
        assert ed.node_at(("stmts", 0, "dst")) == PAny(name="t")

    def test_constant_value_and_width(self):
        ed = PatternEditor(_pattern())
        path = ("stmts", 0, "src", "operands", 1)
        ed.set_const(path, None)
        assert ed.node_at(path) == PConst()
        ed.set_const(path, 0x10, bits=32)
        assert ed.node_at(path) == PConst(value=0x10, bits=32)

    def test_sizes_and_operators(self):
        ed = PatternEditor(_pattern())
        ed.set_load_size(("stmts", 1, "value"), None)
        assert ed.node_at(("stmts", 1, "value")).size is None
        ed.set_load_size(("stmts", 1), 4)
        assert ed.node_at(("stmts", 1)).size == 4
        ed.set_ops(("stmts", 0, "src"), frozenset({"Add", "Sub"}))
        assert ed.node_at(("stmts", 0, "src")).op == frozenset({"Add", "Sub"})

    def test_edit_inside_a_choice_rebuilds_it(self):
        ed = PatternEditor(_pattern())
        path = ("stmts", 2, "src", "alternatives", 1)
        ed.set_const(path, 7)
        choice = ed.node_at(("stmts", 2, "src"))
        assert isinstance(choice, PChoice)
        assert choice.alternatives[1] == PConst(value=7)

    def test_everything_off_the_path_is_shared(self):
        ed = PatternEditor(_pattern())
        before = ed.pattern.pattern.stmts[2]
        ed.set_const(("stmts", 0, "src", "operands", 1), 9)
        assert ed.pattern.pattern.stmts[2] is before

    def test_envelope_and_params(self):
        ed = PatternEditor(_pattern())
        ed.set_call_name("do_it")
        ed.set_returnty("unsigned long")
        ed.set_param_type("a0", "char *")
        ed.add_param("t", "int")
        ed.remove_param("a1")
        p = ed.pattern
        assert p.call_name == "do_it"
        assert p.returnty == "unsigned long"
        assert [(x.capture, x.type) for x in p.params] == [("a0", "char *"), ("t", "int")]
        with self.assertRaises(KeyError):
            ed.set_param_type("nope", "int")

    def test_loosen_constants_is_one_undoable_sweep(self):
        ed = PatternEditor(_pattern())
        assert ed.loosen_constants() == 3, "8, and the two choice alternatives"
        assert ed.node_at(("stmts", 0, "src", "operands", 1)) == PConst()
        assert ed.node_at(("stmts", 2, "src", "alternatives", 0)) == PConst()
        assert ed.loosen_constants() == 0
        assert ed.undo()
        assert ed.node_at(("stmts", 0, "src", "operands", 1)) == PConst(value=8)

    def test_edits_round_trip_through_json(self):
        ed = PatternEditor(_pattern())
        ed.set_leaf_mode(("stmts", 1), "optional")
        ed.set_const(("stmts", 0, "src", "operands", 1), None)
        back = PatternEditor.from_dict(ed.to_dict())
        assert back.pattern == ed.pattern

    def test_type_errors_name_the_node(self):
        ed = PatternEditor(_pattern())
        with self.assertRaises(TypeError):
            ed.set_const(("stmts", 0, "dst"), 1)
        with self.assertRaises(TypeError):
            ed.set_expr_wildcard(("stmts", 0))


class TestDescribe(unittest.TestCase):
    def test_labels(self):
        ed = PatternEditor(_pattern())
        assert describe(ed.node_at(("stmts", 0))) == "assign"
        assert describe(ed.node_at(("stmts", 0, "src"))) == "Add"
        assert describe(ed.node_at(("stmts", 0, "src", "operands", 0))) == "var [a0]"
        assert describe(ed.node_at(("stmts", 0, "src", "operands", 1))) == "const 0x8"
        assert describe(ed.node_at(("stmts", 1))) == "store8"
        assert describe(ed.node_at(("stmts", 1, "value"))) == "load8"
        assert describe(PAnyStmt()) == "any statement"
        assert describe(PBinOp(frozenset({"Add", "Sub"}), (PAny(), PAny()))) == "Add|Sub"


if __name__ == "__main__":
    unittest.main()
