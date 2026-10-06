#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Extract,
    FunctionLikeMacro,
    Insert,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, SideEffectStatement
from angr.analyses.decompiler.expression_narrower import EffectiveSizeExtractor
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

l = logging.getLogger(__name__)


class TestNarrowingExpressions(unittest.TestCase):
    def test_dirty_expression_children_are_full_width_uses(self):
        operand = VirtualVariable(0, 41, 64, VirtualVariableCategory.REGISTER, oident=8)
        guard = VirtualVariable(1, 42, 1, VirtualVariableCategory.TMP, oident=0)
        maddr = VirtualVariable(2, 43, 64, VirtualVariableCategory.REGISTER, oident=16)
        dirty = DirtyExpression(
            3,
            "helper",
            [operand],
            guard=guard,
            mfx="Ifx_Read",
            maddr=maddr,
            msize=8,
            bits=64,
        )
        dst = VirtualVariable(4, 44, 64, VirtualVariableCategory.REGISTER, oident=24)

        walker = EffectiveSizeExtractor()
        walker.walk_statement(Assignment(5, dst, dirty))

        self.assertEqual(walker.vvar_effective_bits[operand.varid][operand.idx], (0, 64))
        self.assertEqual(walker.vvar_effective_bits[guard.varid][guard.idx], (0, 1))
        self.assertEqual(walker.vvar_effective_bits[maddr.varid][maddr.idx], (0, 64))

    def test_side_effect_statement_ignores_non_call_expression(self):
        operand = VirtualVariable(0, 45, 64, VirtualVariableCategory.REGISTER, oident=8)
        dirty = DirtyExpression(1, "helper", [operand], bits=64)

        walker = EffectiveSizeExtractor()
        walker.walk_statement(SideEffectStatement(2, dirty))

        self.assertNotIn(operand.varid, walker.vvar_effective_bits)
        self.assertNotIn(operand.varid, walker.vvar_call_arg_effective_bits)

    def test_side_effect_statement_preserves_call_argument_handling(self):
        for expr_type in (Call, FunctionLikeMacro):
            with self.subTest(expr_type=expr_type.__name__):
                argument = VirtualVariable(0, 46, 64, VirtualVariableCategory.REGISTER, oident=8)
                converted_argument = Convert(1, 64, 32, False, argument)
                call = expr_type(2, "callee", args=[converted_argument], bits=64)

                walker = EffectiveSizeExtractor()
                walker.walk_statement(SideEffectStatement(3, call))

                self.assertEqual(walker.vvar_call_arg_effective_bits[argument.varid], (0, 32))
                self.assertNotIn(argument.varid, walker.vvar_effective_bits)

    def test_insert_base_is_a_full_width_use(self):
        # the base of an Insert is consumed at full width: every byte outside the inserted range is
        # preserved into the result. EffectiveSizeExtractor used to skip the base entirely, so a vvar
        # whose only other uses were narrow (e.g. an ah-style Extract) was narrowed below the width
        # of the Insert base and zero-extended back, destroying the preserved bytes:
        #     v1 = a0->field_10; a0->field_10 = _INSERT(v1, 1, v1 & 239);   // v1 narrowed to char
        # instead of the full-width read-modify-write of field_10.
        base = VirtualVariable(1, 44, 64, VirtualVariableCategory.REGISTER, oident=16)
        ah_vvar = VirtualVariable(4, 44, 64, VirtualVariableCategory.REGISTER, oident=16)
        ah_read = Extract(3, 8, ah_vvar, Const(5, 1, 64), "Iend_LE")
        value = BinaryOp(2, "And", [ah_read, Const(6, 239, 8)], False, bits=8)
        dst = VirtualVariable(7, 48, 64, VirtualVariableCategory.REGISTER, oident=16)
        stmt = Assignment(9, dst, Insert(8, base, Const(10, 1, 64), value, "Iend_LE"))

        walker = EffectiveSizeExtractor()
        walker.walk_statement(stmt)

        occurrences = walker.vvar_effective_bits[44]
        # the Insert-base occurrence must be recorded as a full-width use...
        assert occurrences[base.idx] == (0, 64)
        # ...while the byte-1 Extract occurrence stays narrow
        assert occurrences[ah_vvar.idx] == (8, 16)
        assert 44 in walker.vvars_used_as_insert_base

    def test_narrowing_expressions_after_making_callsite_only(self):
        # narrowing expressions before making callsites may incorrectly remove some definitions that the calls use
        # in this test case, the definition of ecx at block 0x4066E5 will be replaced by cl, but ecx is actually used
        # by the call at 0x4066F8
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
            start_at_entry=False,
            regions=[(0x406480, 0x406480 + 5000)],
        )

        func = cfg.functions[0x406480]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # should not crash!


if __name__ == "__main__":
    unittest.main()
