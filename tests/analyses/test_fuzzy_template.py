#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.decompiler.known_patterns import (
    PAny,
    PAnyStmt,
    PAssign,
    PBinOp,
    PCall,
    PCallStmt,
    PChoice,
    PCondJump,
    PConst,
    PConv,
    PField,
    PLoad,
    PPhi,
    PStore,
    PVVar,
)
from angr.analyses.decompiler.known_patterns.generator import PatternGenerationError, PatternGenerator
from angr.analyses.fuzzy_patterns import tokenize
from angr.analyses.fuzzy_patterns.template import TEMPLATE_TOKENIZER, Fit, match_shape, parse_shape, shape_of
from tests.common import bin_location

BIN_PATH = os.path.join(bin_location, "tests")


def _fit(node, shape):
    return match_shape(node, parse_shape(shape))


class TestParseShape(unittest.TestCase):
    def test_nested_shape(self):
        assert parse_shape("Asn(V,Add(V,C))") == ("Asn", (("V", ()), ("Add", (("V", ()), ("C", ())))))

    def test_call_head_keeps_its_brackets(self):
        assert parse_shape("SE(Call[foo,bar]/2)") == ("SE", (("Call[foo,bar]/2", ()),))

    def test_leaf(self):
        assert parse_shape("L") == ("L", ())


class TestShapeOf(unittest.TestCase):
    """A concrete node renders to the one shape the tokenizer would give its statement."""

    def test_assignment(self):
        node = PAssign(PVVar(), PBinOp("Add", (PVVar(), PConst(value=4))))
        assert shape_of(node) == "Asn(V,Add(V,C))"

    def test_store_and_load_carry_sizes(self):
        assert shape_of(PStore(PVVar(), PLoad(PVVar(), size=4), size=8)) == "St8(V,Ld4(V))"

    def test_conversions_vanish(self):
        assert shape_of(PAssign(PVVar(), PConv(PVVar(), 32, 64))) == "Asn(V,V)"

    def test_call_statement_both_spellings(self):
        call = PCall(frozenset({"free"}), args=(PVVar(),))
        assert shape_of(PCallStmt(call)) == "SE(Call[free]/1)"
        assert shape_of(PCallStmt(call, dst=PVVar())) == "Asn(V,Call[free]/1)"

    def test_field_access(self):
        assert shape_of(PAssign(PVVar(), PLoad(PField("s", 8), size=8))) == "Asn(V,Ld8(Add(V,C)))"
        assert shape_of(PAssign(PVVar(), PLoad(PField("s", 0), size=8))) == "Asn(V,Ld8(V))"

    def test_wildcards_have_no_single_shape(self):
        assert shape_of(PAssign(PVVar(), PAny())) is None
        assert shape_of(PStore(PVVar(), PVVar())) is None, "an unsized store stands for every size"
        assert shape_of(PAssign(PVVar(), PBinOp(frozenset({"Add", "Sub"}), (PVVar(), PVVar())))) is None
        assert shape_of(PCondJump(PVVar())) is None, "branch directions are not part of the pattern"
        assert shape_of(PAnyStmt()) is None

    def test_depth_cut_matches_the_tokenizer(self):
        deep = PVVar()
        for _ in range(6):
            deep = PBinOp("Add", (deep, PConst()))
        shape = shape_of(PAssign(PVVar(), deep))
        assert shape is not None
        assert "?" in shape, "past the tokenizer's depth the rendering is cut to ?"


class TestMatchShape(unittest.TestCase):
    def test_exact(self):
        node = PAssign(PVVar(), PBinOp("Add", (PVVar(), PConst())))
        assert _fit(node, "Asn(V,Add(V,C))") is Fit.EXACT
        assert _fit(node, "Asn(VR,Add(VS,C))") is Fit.EXACT, "a categorized stream still fits"

    def test_operator_class_gives_partial_credit(self):
        node = PAssign(PVVar(), PBinOp("Add", (PVVar(), PConst())))
        assert _fit(node, "Asn(V,Sub(V,C))") is Fit.KLASS
        assert _fit(node, "Asn(V,Shl(V,C))") is Fit.NONE

    def test_operator_sets(self):
        node = PAssign(PVVar(), PBinOp(frozenset({"Shl", "Shr"}), (PVVar(), PConst())))
        assert _fit(node, "Asn(V,Shr(V,C))") is Fit.EXACT
        assert _fit(node, "Asn(V,Sar(V,C))") is Fit.KLASS
        assert _fit(node, "Asn(V,Add(V,C))") is Fit.NONE

    def test_wildcards_accept_anything(self):
        assert _fit(PAnyStmt(), "St8(V,Ld4(V))") is Fit.EXACT
        assert _fit(PAssign(PVVar(), PAny()), "Asn(V,Call[f]/3)") is Fit.EXACT
        assert _fit(PStore(PAny(), PAny()), "St4(V,C)") is Fit.EXACT
        assert _fit(PStore(PAny(), PAny(), size=8), "St4(V,C)") is Fit.NONE

    def test_statement_kind_must_agree(self):
        assert _fit(PAssign(PAny(), PAny()), "St8(V,C)") is Fit.NONE
        assert _fit(PCondJump(PAny()), "CJfb(CmpEQ(V,C))") is Fit.EXACT

    def test_cut_off_token_fits_any_subtree(self):
        node = PAssign(PVVar(), PBinOp("Add", (PLoad(PVVar(), size=8), PConst())))
        assert _fit(node, "Asn(V,Add(?,C))") is Fit.EXACT

    def test_choice_takes_its_best_alternative(self):
        node = PAssign(PVVar(), PChoice(PBinOp("Shl", (PVVar(), PConst())), PBinOp("Add", (PVVar(), PConst()))))
        assert _fit(node, "Asn(V,Sub(V,C))") is Fit.KLASS

    def test_calls(self):
        node = PCallStmt(PCall(frozenset({"free", "cfree"}), args=(PAny(),)))
        assert _fit(node, "SE(Call[free]/1)") is Fit.EXACT
        assert _fit(node, "SE(Call[free]/2)") is Fit.NONE
        assert _fit(node, "SE(Call[malloc]/1)") is Fit.NONE
        assert _fit(PCallStmt(PCall(frozenset())), "SE(Call[anything]/9)") is Fit.EXACT

    def test_phi(self):
        assert _fit(PAssign(PVVar(), PPhi()), "Asn(V,Phi3)") is Fit.EXACT


class TestMirrorsTheTokenizer(unittest.TestCase):
    """Rendering an AIL statement through the generator and then shape_of must land on
    the tokenizer's shape, and match_shape must accept it, for every statement of a
    real function. This is what keeps the two canonicalizations from drifting."""

    def test_every_statement_of_real_functions(self):
        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)

        exact = wildcard = 0
        for name in ("doit", "convert"):
            func = proj.kb.functions[name]
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            assert dec.ail_graph is not None and dec.codegen is not None

            entry = next(b for b in dec.ail_graph if b.addr == func.addr)
            stream = tokenize(dec.ail_graph, entry, **TEMPLATE_TOKENIZER)
            gen = PatternGenerator(dec.codegen, dec.ail_graph)
            blocks = {(b.addr, b.idx): b for b in dec.ail_graph}

            for loc, shape in zip(stream.locs, stream.shapes):
                stmt = blocks[loc.block_loc].statements[loc.stmt_idx]
                try:
                    node = gen._gen_stmt(stmt, {}, set())
                except PatternGenerationError:
                    node = PAnyStmt()
                assert match_shape(node, parse_shape(shape)) is not Fit.NONE, f"{shape} rejected by its own node"
                rendered = shape_of(node)
                if rendered is None:
                    wildcard += 1
                    continue
                exact += 1
                assert rendered == shape, f"shape_of gave {rendered}, the tokenizer gave {shape}"

        # 32 concrete statements out of 555 at the time of writing; most statements hold a
        # call, a stack reference or a phi, which the generator renders as a wildcard
        assert exact >= 25, f"only {exact} concrete statements; the mirror is barely exercised"
        assert wildcard > exact


if __name__ == "__main__":
    unittest.main()
