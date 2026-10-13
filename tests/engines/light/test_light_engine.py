#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
from collections import defaultdict
from types import SimpleNamespace
from typing import Any
from unittest import TestCase, main

import archinfo

import angr
from angr import ailment, claripy
from angr.ailment.expression import BinaryOp, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.optimization_passes.engine_base import SimplifierAILEngine, SimplifierAILState
from angr.analyses.decompiler.optimization_passes.inlined_string_transformation_simplifier import (
    InlinedStringTransformationAILEngine,
)
from angr.analyses.purity.engine import DataSource, PurityEngineAIL
from angr.analyses.reaching_definitions.engine_ail import SimEngineRDAIL
from angr.analyses.typehoon.typevars import ConvertTo, DerivedTypeVariable, TypeVariable, TypeVariableManager
from angr.analyses.variable_recovery.engine_ail import SimEngineVRAIL
from angr.analyses.variable_recovery.engine_base import RichR
from angr.engines.light.engine import longest_prefix_lookup
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from tests.common import bin_location


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

    def test_variable_recovery_convert_replaces_an_existing_conversion(self):
        base_typevar = TypeVariable(name="conv_base")
        engine: Any = object.__new__(SimEngineVRAIL)
        engine.tv_manager = TypeVariableManager(0x400000)
        converted = engine.tv_manager.new_dtv_with_merged_labels(base_typevar, label=ConvertTo(32))
        engine._expr = lambda expr: RichR(claripy.BVV(0, 32), typevar=converted)
        engine.state = SimpleNamespace(
            top=lambda bits: claripy.BVS("vr_conv_top", bits),
            add_type_constraint=lambda tc: None,
        )
        conv = ailment.Expr.Convert(1, 32, 64, False, ailment.Expr.Const(0, 0, 32))

        result = engine._handle_expr_Convert(conv)

        # the existing conversion is replaced, not stacked on top of
        assert isinstance(result.typevar, DerivedTypeVariable)
        assert result.typevar.type_var is base_typevar
        assert len(result.typevar.labels) == 1
        assert isinstance(result.typevar.labels[0], ConvertTo)
        assert result.typevar.labels[0].to_bits == 64

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

    def test_purity_cas_reads_and_writes_the_pointer(self):
        pointer = frozenset((DataSource(function_arg=0),))
        data = frozenset((DataSource(constant_value=1),))
        loaded = frozenset((DataSource(function_arg=1),))
        provenance = {0: pointer, 1: data, 2: frozenset()}
        engine: Any = object.__new__(PurityEngineAIL)
        engine.state = SimpleNamespace(vars=defaultdict(frozenset))
        engine.tmps = {}
        loads: list[Any] = []
        stores: list[Any] = []
        engine._expr = lambda expr: provenance[expr.idx]
        engine._do_load = lambda ptr: (loads.append(ptr), loaded)[1]
        engine._do_store = lambda ptr, val: stores.append((ptr, val))
        old = VirtualVariable(3, 7, 32, VirtualVariableCategory.REGISTER, oident=16)
        stmt = ailment.Stmt.CAS(
            4,
            ailment.Expr.Const(0, 0x400000, 64),
            ailment.Expr.Const(1, 1, 32),
            None,
            ailment.Expr.Const(2, 0, 32),
            None,
            old,
            None,
            "Iend_LE",
        )

        assert engine._handle_stmt_CAS(stmt) is None

        # a compare-and-swap reads the location and conditionally writes it, so the pointer gets both uses
        assert loads == [pointer]
        assert stores == [(pointer, data)]
        # and the old value it hands back is what reading the location produced
        assert engine.state.vars[7] is loaded

    def test_purity_double_width_cas_assigns_both_destinations(self):
        pointer = frozenset((DataSource(function_arg=0),))
        loaded = frozenset((DataSource(function_arg=1),))
        engine: Any = object.__new__(PurityEngineAIL)
        engine.state = SimpleNamespace(vars=defaultdict(frozenset))
        engine.tmps = {}
        engine._expr = lambda expr: pointer if expr.idx == 0 else frozenset()
        engine._do_load = lambda ptr: loaded
        engine._do_store = lambda ptr, val: None
        lo = VirtualVariable(5, 11, 64, VirtualVariableCategory.STACK, oident=0)
        hi = VirtualVariable(6, 12, 64, VirtualVariableCategory.STACK, oident=8)
        stmt = ailment.Stmt.CAS(
            7,
            ailment.Expr.Const(0, 0x400000, 64),
            ailment.Expr.Const(1, 1, 64),
            ailment.Expr.Const(2, 2, 64),
            ailment.Expr.Const(3, 0, 64),
            ailment.Expr.Const(4, 0, 64),
            lo,
            hi,
            "Iend_LE",
        )

        assert engine._handle_stmt_CAS(stmt) is None

        # a double-width compare-and-swap hands back two old values; leaving either unset would read as no provenance
        assert engine.state.vars[11] is loaded
        assert engine.state.vars[12] is loaded

    def test_purity_weak_assignment_keeps_both_provenances(self):
        existing = frozenset((DataSource(function_arg=0),))
        incoming = frozenset((DataSource(function_arg=1),))
        engine: Any = object.__new__(PurityEngineAIL)
        engine.state = SimpleNamespace(vars=defaultdict(frozenset, {7: existing}))
        engine.tmps = {}
        engine._expr = lambda expr: incoming
        dst = VirtualVariable(0, 7, 64, VirtualVariableCategory.STACK, oident=0)
        stmt = ailment.Stmt.WeakAssignment(2, dst, ailment.Expr.Const(1, 3, 64))

        assert engine._handle_stmt_WeakAssignment(stmt) is None

        # the destination may or may not take the source's value, so it ends up with either provenance
        assert engine.state.vars[7] == existing | incoming


class TestUnknownAILOperations(TestCase):
    def test_an_operation_without_a_handler_is_unknown_not_a_crash(self):
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        engine = SimplifierAILEngine(proj)
        engine.state = SimplifierAILState(proj.arch)
        vvar = VirtualVariable(0, 1, 128, VirtualVariableCategory.REGISTER, oident=16)
        binop = BinaryOp(1, "PermOrZeroV", [vvar, vvar], False, bits=128)
        unop = UnaryOp(2, "SomethingNew", vvar, bits=128)
        assert engine._handle_expr_BinaryOp(binop) in (None, binop)
        assert engine._handle_expr_UnaryOp(unop) in (None, unop)


class TestVectorConversionUnops(TestCase):
    """
    A lane-wise VEX conversion spells lane widths in its name, so the widths parsed out of the name
    are not the operand's and the result's and it must not reach the scalar conversion handler.
    Each of the four functions named below is one NEON vcvt form.
    """

    FUNCTIONS = (
        ("truncate_to_ints", "Iop_F32toI32Sx4_RZ"),
        ("truncate_to_uints", "Iop_F32toI32Ux4_RZ"),
        ("ints_to_floats", "Iop_I32StoF32x4_DEP"),
        ("uints_to_floats", "Iop_I32UtoF32x4_DEP"),
    )

    def test_a_lane_wise_conversion_does_not_reach_the_scalar_handler(self):
        proj = angr.Project(os.path.join(bin_location, "tests", "armhf", "vector_conversions"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)

        for name, op in self.FUNCTIONS:
            with self.subTest(function=name):
                assert name in cfg.functions, f"fixture no longer contains {name}"
                func = cfg.functions[name]
                operations = {o for addr in func.block_addrs_set for o in proj.factory.block(addr).vex.operations}
                assert op in operations, f"{name} no longer lifts to {op}"

                # Each of these used to die on the same operation: AssertionError out of the
                # reaching-definitions and propagator conversion handlers, TypeError out of variable
                # recovery, whose handler asks the state for a top of to_size bits and to_size is None.
                proj.analyses.ReachingDefinitions(subject=func, observe_all=False)
                proj.analyses.Propagator(func=func)
                proj.analyses.XRefs(func=func)
                proj.analyses.VariableRecoveryFast(func)


if __name__ == "__main__":
    main()
