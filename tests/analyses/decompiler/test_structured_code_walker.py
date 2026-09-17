#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.decompiler.structured_codegen.c import (
    CStructuredCodeWalker,
    CTypeCast,
    CVectorConvert,
    CVEXCCallExpression,
    qualifies_for_implicit_cast,
)
from angr.analyses.decompiler.structured_codegen.rust import (
    RustStructuredCodeWalker,
    RustVectorConvert,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _CCollector(CStructuredCodeWalker):
    """Records every node the walker dispatches on."""

    def __init__(self):
        self.visited = []

    def handle(self, obj):
        self.visited.append(obj)
        return super().handle(obj)


class _RustCollector(RustStructuredCodeWalker):
    """Records every node the walker dispatches on."""

    visited: list = []

    @classmethod
    def handle(cls, obj):
        cls.visited.append(obj)
        return super().handle(obj)


def _walk(codegen):
    walker = _CCollector()
    walker.handle(codegen.cfunc)
    return walker.visited


class TestWalkerDescendsIntoVectorConverts(unittest.TestCase):
    """CVectorConvert/RustVectorConvert hold an operand subtree; the walkers must descend into it so that passes
    such as MakeTypecastsImplicit reach it."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "vector_conversions"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.func = cls.proj.kb.functions.function(name="truncate_to_ints")

    def test_c_walker_visits_operand(self):
        dec = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model)
        visited = _walk(dec.codegen)
        converts = [node for node in visited if isinstance(node, CVectorConvert)]
        assert converts, "the binary no longer decompiles to a lane-wise conversion"
        for convert in converts:
            assert any(node is convert.operand for node in visited)

    def test_rust_walker_visits_operand(self):
        dec = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model, flavor="rust")
        _RustCollector.visited = []
        _RustCollector.handle(dec.codegen.rust_func)
        visited = _RustCollector.visited
        converts = [node for node in visited if isinstance(node, RustVectorConvert)]
        assert converts, "the binary no longer decompiles to a lane-wise conversion"
        for convert in converts:
            assert any(node is convert.operand for node in visited)


class TestWalkerDescendsIntoCCallOperands(unittest.TestCase):
    """CVEXCCallExpression holds its operands; the walkers must descend into them."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.proj.analyses.CompleteCallingConventions()
        cls.func = cls.proj.kb.functions.function(name="authenticate")

    def test_c_walker_visits_operands(self):
        dec = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model)
        visited = _walk(dec.codegen)
        ccalls = [node for node in visited if isinstance(node, CVEXCCallExpression)]
        assert ccalls, "the binary no longer decompiles to a VEX ccall"
        for ccall in ccalls:
            for operand in ccall.operands:
                assert any(node is operand for node in visited)

    def test_implicit_casts_collapse_inside_ccall_operands(self):
        # reaching the operands means MakeTypecastsImplicit gets to drop the casts C would perform anyway
        dec = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model)
        for ccall in (node for node in _walk(dec.codegen) if isinstance(node, CVEXCCallExpression)):
            for operand in ccall.operands:
                assert not (
                    isinstance(operand, CTypeCast) and qualifies_for_implicit_cast(operand.src_type, operand.dst_type)
                ), f"redundant cast left in a ccall operand: {operand}"


if __name__ == "__main__":
    unittest.main()
