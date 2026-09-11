#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest import TestCase, main

import archinfo

from angr import ailment, claripy
from angr.analyses.decompiler.optimization_passes.engine_base import SimplifierAILEngine
from angr.analyses.decompiler.optimization_passes.inlined_string_transformation_simplifier import (
    InlinedStringTransformationAILEngine,
)
from angr.analyses.purity.engine import DataSource, PurityEngineAIL
from angr.analyses.reaching_definitions.engine_ail import SimEngineRDAIL
from angr.analyses.typehoon.typevars import TypeVariable
from angr.analyses.variable_recovery.engine_ail import SimEngineVRAIL
from angr.analyses.variable_recovery.engine_base import RichR
from angr.engines.light.engine import longest_prefix_lookup
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues


class TestLightEngine(TestCase):
    def test_unop_handler(self):

        def handle_unop_32to1():
            pass

        mapping = {
            "32to1": handle_unop_32to1,
        }

        assert longest_prefix_lookup("32to1", mapping) is handle_unop_32to1
        assert longest_prefix_lookup("32to1_foo", mapping) is handle_unop_32to1
        assert longest_prefix_lookup("32to", mapping) is None

    def test_ail_abs_unop_dispatch(self):
        arch = archinfo.ArchAMD64()
        engine = SimplifierAILEngine(SimpleNamespace(arch=arch))  # pyright: ignore[reportArgumentType]
        operand = ailment.Expr.Const(0, 1.0, 32)  # pyright: ignore[reportArgumentType]

        abs_expr = ailment.Expr.UnaryOp(1, "Abs", operand)
        assert engine._handle_expr_UnaryOp(abs_expr) is abs_expr

    def test_inlined_string_abs_visits_operand(self):
        engine: Any = object.__new__(InlinedStringTransformationAILEngine)
        seen = []
        engine._expr = seen.append
        operand = ailment.Expr.Const(0, 1.0, 32)  # pyright: ignore[reportArgumentType]
        abs_expr = ailment.Expr.UnaryOp(1, "Abs", operand)

        engine._handle_unop_Abs(abs_expr)

        assert seen == [operand]

    def test_rda_abs_visits_operand(self):
        engine: Any = object.__new__(SimEngineRDAIL)
        seen = []
        engine._expr = lambda expr: (seen.append(expr), MultiValues(claripy.BVV(0, expr.bits)))[1]
        engine.state = SimpleNamespace(top=lambda bits: claripy.BVS("rda_abs_top", bits))
        operand = ailment.Expr.Const(0, 0, 32)
        abs_expr = ailment.Expr.UnaryOp(1, "Abs", operand)

        result = engine._handle_unop_Abs(abs_expr)

        assert seen == [operand]
        assert isinstance(result, MultiValues)

    def test_rda_dirty_expression_visits_inputs(self):
        engine: Any = object.__new__(SimEngineRDAIL)
        engine.state = SimpleNamespace(top=lambda bits: claripy.BVS("rda_dirty_top", bits))
        operand = ailment.Expr.Const(0, 1, 32)
        guard = ailment.Expr.Const(1, 1, 1)
        memory_address = ailment.Expr.Const(2, 0x4000, 64)
        cases = (
            (guard, memory_address, [operand, guard, memory_address]),
            (None, None, [operand]),
        )

        for current_guard, current_address, expected in cases:
            with self.subTest(guard=current_guard, memory_address=current_address):
                seen = []
                engine._expr = seen.append
                dirty_expr = ailment.Expr.DirtyExpression(
                    3,
                    "helper",
                    [operand],
                    guard=current_guard,
                    mfx="read",
                    maddr=current_address,
                    msize=4,
                    bits=32,
                )

                result = engine._handle_expr_DirtyExpression(dirty_expr)

                self.assertEqual(seen, expected)
                self.assertIsInstance(result, MultiValues)
                value = result.one_value()
                self.assertIsNotNone(value)
                self.assertEqual(len(value), 32)

    def test_variable_recovery_abs_preserves_typevar(self):
        operand_typevar = TypeVariable(name="abs_operand")
        engine: Any = object.__new__(SimEngineVRAIL)
        seen = []
        engine._expr = lambda expr: (
            seen.append(expr),
            RichR(claripy.BVV(0, expr.bits), typevar=operand_typevar),
        )[1]
        engine.state = SimpleNamespace(top=lambda bits: claripy.BVS("vr_abs_top", bits))
        operand = ailment.Expr.Const(0, 0, 32)
        abs_expr = ailment.Expr.UnaryOp(1, "Abs", operand)

        result = engine._handle_unop_Abs(abs_expr)

        assert seen == [operand]
        assert result.typevar is operand_typevar
        assert len(result.data) == 32

    def test_purity_abs_preserves_provenance(self):
        provenance = frozenset((DataSource(function_arg=0),))
        engine: Any = object.__new__(PurityEngineAIL)
        seen = []
        engine._expr_noconst = lambda expr: (seen.append(expr), provenance)[1]
        operand = ailment.Expr.Const(0, 0, 32)
        abs_expr = ailment.Expr.UnaryOp(1, "Abs", operand)

        result = engine._handle_unop_Abs(abs_expr)

        assert seen == [operand]
        assert result is provenance


class TestUnknownAILOperations(TestCase):
    def test_an_operation_without_a_handler_is_unknown_not_a_crash(self):
        # The AIL side looked operations up in its handler table and raised KeyError on one it had no handler for
        # (vector ops such as PermOrZeroV). It now goes to the Default handlers like the VEX side does.
        # pylint:disable=import-outside-toplevel
        import os

        import angr
        from angr.ailment.expression import BinaryOp, UnaryOp, VirtualVariable, VirtualVariableCategory
        from angr.analyses.decompiler.optimization_passes.engine_base import SimplifierAILEngine, SimplifierAILState
        from tests.common import bin_location

        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        engine = SimplifierAILEngine(proj)
        engine.state = SimplifierAILState(proj.arch)
        vvar = VirtualVariable(0, 1, 128, VirtualVariableCategory.REGISTER, oident=16)
        binop = BinaryOp(1, "PermOrZeroV", [vvar, vvar], False, bits=128)
        unop = UnaryOp(2, "SomethingNew", vvar, bits=128)
        # the simplifier's own Default handlers hand the expression back; the base's yield an unknown value
        assert engine._handle_expr_BinaryOp(binop) in (None, binop)
        assert engine._handle_expr_UnaryOp(unop) in (None, unop)


if __name__ == "__main__":
    main()
