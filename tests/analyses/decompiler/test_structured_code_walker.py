#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIfElse,
    CStatements,
    CStructuredCodeWalker,
    CTypeCast,
    CVectorConvert,
    CVEXCCallExpression,
    FieldReferenceCleanup,
    MakeTypecastsImplicit,
    PointerArithmeticFixer,
    qualifies_for_implicit_cast,
)
from angr.analyses.decompiler.structured_codegen.rust import (
    RustStructuredCodeWalker,
    RustVectorConvert,
)
from angr.sim_type import SimTypeInt
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


class TestWalkersDescendDeepTrees(unittest.TestCase):
    """The walkers must not spend interpreter frames per level of the C tree.

    `FieldReferenceCleanup`, `PointerArithmeticFixer` and `MakeTypecastsImplicit` each walk the whole C tree after
    code generation, and the code generator can hand them a tree hundreds of levels deep -- which it does whenever
    structuring degrades and a large function's statements come out as a long if-chain. Descending recursively cost
    two frames a level, so past about 490 levels each of those passes raised RecursionError and the function came back
    with no code at all.
    """

    @classmethod
    def setUpClass(cls):
        # A real code generator: every C node allocates its identity from the one that owns it.
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        cls.codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen

    def _chain(self, depth: int):
        """`depth` levels of CStatements holding one CIfElse, with an empty CStatements at the bottom."""
        codegen = self.codegen
        node = CStatements([], codegen=codegen)
        for i in range(depth):
            condition = CConstant(1, SimTypeInt(), codegen=codegen)
            node = CStatements(
                [CIfElse([(condition, node)], tags={"ins_addr": 0x1000 + i}, codegen=codegen)],
                codegen=codegen,
            )
        return node

    @staticmethod
    def _nesting(obj) -> int:
        """How many CIfElse levels the tree has, counted without recursing."""
        depth = 0
        while True:
            if isinstance(obj, CStatements) and len(obj.statements) == 1:
                obj = obj.statements[0]
            elif isinstance(obj, CIfElse):
                depth += 1
                obj = obj.condition_and_nodes[0][1]
            else:
                return depth

    def test_each_pass_descends_a_tree_deeper_than_the_recursion_limit(self):
        # The recursive descent cleared 200 of these levels and failed at 250.
        depth = 2000
        for pass_cls in (FieldReferenceCleanup, PointerArithmeticFixer, MakeTypecastsImplicit):
            handled = pass_cls().handle(self._chain(depth))
            assert self._nesting(handled) == depth, pass_cls.__name__

    def test_a_subclass_that_replaces_handle_still_sees_every_node(self):
        # _CCollector records in `handle`, so a walk driven on a stack has to route every child back through it.
        collector = _CCollector()
        collector.handle(self._chain(3))
        assert sum(1 for node in collector.visited if isinstance(node, CIfElse)) == 3


if __name__ == "__main__":
    unittest.main()
