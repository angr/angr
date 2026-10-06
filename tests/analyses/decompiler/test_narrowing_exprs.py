#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Extract,
    Insert,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.expression_narrower import EffectiveSizeExtractor, ExpressionNarrower
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

l = logging.getLogger(__name__)


class TestNarrowingExpressions(unittest.TestCase):
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

    def test_narrowing_a_register_variable_moves_the_offset_on_big_endian(self):
        # A narrowed variable keeps the low-order bytes of the original: every use is rewritten to
        # Convert(narrow -> wide) and every definition to Convert(wide -> narrow). On a little-endian
        # architecture those bytes start where the register starts, so its offset is unchanged. On a
        # big-endian one they sit at the end of the register, so the offset must move forward by the
        # number of bytes dropped -- PPC64 r3 is (offset 40, 8 bytes) and its low 4 bytes are at 44.
        # Leaving the offset alone made the narrowed variable name the high-order bytes instead.
        for binary, register, big_endian in (("ppc64", "r3", True), ("x86_64", "rax", False)):
            with self.subTest(binary=binary):
                proj = angr.Project(os.path.join(test_location, binary, "fauxware"), auto_load_libs=False)
                arch = proj.arch
                reg_offset, reg_size = arch.registers[register]
                new_size = reg_size // 2
                bits = reg_size * arch.byte_width

                varid = 0x100
                dst = VirtualVariable(1, varid, bits, VirtualVariableCategory.REGISTER, oident=reg_offset)
                use = VirtualVariable(2, varid, bits, VirtualVariableCategory.REGISTER, oident=reg_offset)
                sink = VirtualVariable(3, 0x101, bits, VirtualVariableCategory.REGISTER, oident=reg_offset)
                block = Block(
                    0x400000,
                    0,
                    statements=[Assignment(10, dst, Const(11, 0, bits)), Assignment(12, sink, use)],
                )

                narrower = ExpressionNarrower(proj, None, Manager(), [], {}, {})
                narrower.new_vvar_sizes[varid] = new_size
                new_block = narrower.walk(block)

                expected = reg_offset + reg_size - new_size if big_endian else reg_offset
                assert (arch.register_endness == "Iend_BE") is big_endian

                new_def_stmt, new_use_stmt = new_block.statements
                assert isinstance(new_def_stmt, Assignment)
                assert isinstance(new_use_stmt, Assignment)

                narrowed_def = new_def_stmt.dst
                assert isinstance(narrowed_def, VirtualVariable)
                assert narrowed_def.size == new_size
                assert narrowed_def.reg_offset == expected

                # the use became Convert(narrow -> wide) around the same narrowed variable
                widened = new_use_stmt.src
                assert isinstance(widened, Convert)
                narrowed_use = widened.operand
                assert isinstance(narrowed_use, VirtualVariable)
                assert narrowed_use.varid == varid
                assert narrowed_use.size == new_size
                assert narrowed_use.reg_offset == expected

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
