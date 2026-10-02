# pylint: disable=protected-access
from __future__ import annotations

import unittest
from functools import partial
from types import SimpleNamespace
from typing import Any, cast

import archinfo

from angr.ailment import Block
from angr.ailment.expression import Const, DirtyExpression, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import DirtyStatement
from angr.analyses.decompiler.dephication.rewriting_engine import SimEngineDephiRewriting
from angr.analyses.decompiler.ssailification.rewriting_engine import SimEngineSSARewriting


def _replace_selected(expr, *, replacements, fields, rewritten_fields):
    return replacements[expr] if fields[expr] in rewritten_fields else None


class TestDirtyExpressionRewriting(unittest.TestCase):
    """Tests metadata-preserving DirtyExpression rewrites."""

    def test_engines_preserve_unchanged_children(self):
        for engine_cls in (SimEngineSSARewriting, SimEngineDephiRewriting):
            for rewritten_fields in ({"maddr"}, {"operand"}, {"guard", "maddr"}):
                with self.subTest(engine=engine_cls.__name__, fields=rewritten_fields):
                    operand = Const(0, 1, 64)
                    guard = Const(1, 1, 1)
                    maddr = Const(2, 0x4000, 64)
                    dirty = DirtyExpression(
                        3,
                        "helper",
                        [operand],
                        guard=guard,
                        mfx="Ifx_Modify",
                        maddr=maddr,
                        msize=4,
                        bits=32,
                        ins_addr=0x400000,
                    )
                    replacements = {
                        operand: Const(4, 2, 64),
                        guard: Const(5, 0, 1),
                        maddr: Const(6, 0x5000, 64),
                    }
                    fields = {operand: "operand", guard: "guard", maddr: "maddr"}

                    engine = object.__new__(engine_cls)
                    engine._expr = partial(
                        _replace_selected,
                        replacements=replacements,
                        fields=fields,
                        rewritten_fields=rewritten_fields,
                    )

                    rewritten = engine._handle_expr_DirtyExpression(dirty)

                    self.assertIsNotNone(rewritten)
                    assert rewritten is not None
                    expected_operand = replacements[operand] if "operand" in rewritten_fields else operand
                    expected_guard = replacements[guard] if "guard" in rewritten_fields else guard
                    expected_maddr = replacements[maddr] if "maddr" in rewritten_fields else maddr
                    self.assertEqual(rewritten.operands[0], expected_operand)
                    self.assertEqual(rewritten.guard, expected_guard)
                    self.assertEqual(rewritten.maddr, expected_maddr)
                    self.assertEqual(rewritten.callee, dirty.callee)
                    self.assertEqual(rewritten.mfx, dirty.mfx)
                    self.assertEqual(rewritten.msize, dirty.msize)
                    self.assertEqual(rewritten.bits, dirty.bits)
                    self.assertEqual(rewritten.tags, dirty.tags)

    def test_dephication_rewrites_memory_address_through_engine(self):
        operand = VirtualVariable(0, 10, 64, VirtualVariableCategory.REGISTER, oident=16)
        unchanged_operand = VirtualVariable(1, 11, 64, VirtualVariableCategory.REGISTER, oident=24)
        guard = VirtualVariable(2, 12, 1, VirtualVariableCategory.TMP, oident=0)
        maddr = VirtualVariable(3, 14, 64, VirtualVariableCategory.REGISTER, oident=32)
        dirty = DirtyExpression(
            4,
            "helper",
            [operand, unchanged_operand],
            guard=guard,
            mfx="Ifx_Modify",
            maddr=maddr,
            msize=8,
            bits=64,
            ins_addr=0x400000,
        )
        block = Block(0x400000, 1, statements=[DirtyStatement(5, dirty)])

        engine = SimEngineDephiRewriting(
            SimpleNamespace(arch=archinfo.ArchAMD64()),
            {operand.varid: 110, maddr.varid: 114},
        )
        engine.process(None, block=block)

        self.assertIsNotNone(engine.out_block)
        assert engine.out_block is not None
        new_stmt = engine.out_block.statements[0]
        self.assertIsInstance(new_stmt, DirtyStatement)
        new_dirty = cast(Any, new_stmt).dirty
        self.assertIsInstance(new_dirty, DirtyExpression)
        self.assertEqual([new_operand.varid for new_operand in new_dirty.operands], [110, unchanged_operand.varid])
        self.assertEqual(new_dirty.guard.varid, guard.varid)
        self.assertEqual(new_dirty.maddr.varid, 114)
        self.assertEqual(new_dirty.callee, dirty.callee)
        self.assertEqual(new_dirty.mfx, dirty.mfx)
        self.assertEqual(new_dirty.msize, dirty.msize)
        self.assertEqual(new_dirty.bits, dirty.bits)
        self.assertEqual(new_dirty.tags, dirty.tags)


if __name__ == "__main__":
    unittest.main()
