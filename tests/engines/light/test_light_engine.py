#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest import TestCase, main

import archinfo
import claripy

from angr import ailment
from angr.ailment.manager import Manager
from angr.analyses.decompiler.optimization_passes.engine_base import SimplifierAILEngine
from angr.analyses.decompiler.optimization_passes.inlined_string_transformation_simplifier import (
    InlinedStringTransformationAILEngine,
)
from angr.analyses.decompiler.peephole_optimizations import RemoveCascadingConversions
from angr.analyses.decompiler.utils import peephole_optimize_expr
from angr.analyses.purity.engine import DataSource, PurityEngineAIL
from angr.analyses.reaching_definitions.engine_ail import SimEngineRDAIL
from angr.analyses.typehoon import typeconsts
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

    def test_variable_recovery_convert_signedness(self):
        operand_typevar = TypeVariable(name="convert_operand")
        constraints = []
        engine: Any = object.__new__(SimEngineVRAIL)
        engine._expr = lambda expr: RichR(claripy.BVV(0, expr.bits), typevar=operand_typevar)
        engine.state = SimpleNamespace(
            add_type_constraint=constraints.append,
            top=lambda bits: claripy.BVS("vr_convert_top", bits),
        )
        engine.tv_manager = SimpleNamespace(
            new_dtv_with_merged_labels=lambda typevar, label: typevar,
        )
        operand = ailment.Expr.VirtualVariable(0, 1, 32, ailment.Expr.VirtualVariableCategory.REGISTER, oident=0)

        for expr, expect_unsigned_constraint in (
            (ailment.Expr.Convert(1, 32, 64, False, operand), True),
            (ailment.Expr.Convert(1, 32, 64, False, operand, narrowing_adapter=True), False),
        ):
            with self.subTest(narrowing_adapter=expr.tags.get("narrowing_adapter", False)):
                constraints.clear()
                engine._handle_expr_Convert(expr)
                signedness_constraints = [
                    constraint for constraint in constraints if isinstance(constraint.super_type, typeconsts.UInt32)
                ]
                assert bool(signedness_constraints) is expect_unsigned_constraint

        constraints.clear()
        engine._handle_expr_Convert(ailment.Expr.Convert(1, 64, 32, False, operand))
        assert not constraints

        constraints.clear()
        engine._handle_expr_Convert(
            ailment.Expr.Convert(
                1,
                32,
                64,
                True,
                operand,
                from_type=ailment.Expr.Convert.TYPE_FP,
                to_type=ailment.Expr.Convert.TYPE_FP,
            )
        )
        assert not constraints

    def test_narrowing_adapter_survives_conversion_peepholes(self):
        manager = Manager(arch=archinfo.ArchAMD64())
        operand = ailment.Expr.VirtualVariable(
            manager.next_atom(), 1, 8, ailment.Expr.VirtualVariableCategory.REGISTER, oident=0
        )

        def optimize_and_recover(expr):
            optimized = peephole_optimize_expr(expr, [RemoveCascadingConversions(None, None, manager)])
            assert isinstance(optimized, ailment.Expr.Convert)
            assert isinstance(optimized.operand, ailment.Expr.Convert)

            operand_typevar = TypeVariable(name="narrowing_adapter_operand")
            constraints = []
            engine: Any = object.__new__(SimEngineVRAIL)
            engine.state = SimpleNamespace(
                add_type_constraint=constraints.append,
                top=lambda bits: claripy.BVS("vr_narrowing_adapter_top", bits),
            )
            engine.tv_manager = SimpleNamespace(
                new_dtv_with_merged_labels=lambda typevar, label: typevar,
            )

            def handle_expr(inner_expr):
                if isinstance(inner_expr, ailment.Expr.Convert):
                    return engine._handle_expr_Convert(inner_expr)
                return RichR(claripy.BVV(0, inner_expr.bits), typevar=operand_typevar)

            engine._expr = handle_expr
            engine._handle_expr_Convert(optimized)
            return optimized, constraints

        adapter = ailment.Expr.Convert(manager.next_atom(), 8, 64, False, operand, narrowing_adapter=True)
        outer = ailment.Expr.Convert(manager.next_atom(), 64, 32, False, adapter)
        optimized, constraints = optimize_and_recover(outer)
        assert optimized.operand.tags.get("narrowing_adapter") is True
        assert not constraints

        genuine_widening = ailment.Expr.Convert(manager.next_atom(), 8, 16, False, operand)
        adapter = ailment.Expr.Convert(manager.next_atom(), 16, 32, False, genuine_widening, narrowing_adapter=True)
        optimized, constraints = optimize_and_recover(adapter)
        assert optimized.tags.get("narrowing_adapter") is True
        assert any(isinstance(constraint.super_type, typeconsts.UInt8) for constraint in constraints)

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


if __name__ == "__main__":
    main()
