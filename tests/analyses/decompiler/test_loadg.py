#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from typing import Any, cast

import pyvex

import angr
from angr import ailment
from angr.analyses.decompiler.decompilation_options import get_structurer_option
from tests.common import bin_location, print_decompilation_result


class TestLoadG(unittest.TestCase):
    def test_thumb_complementary_loads(self):
        path = os.path.join(bin_location, "tests", "armel", "decompiler", "loadg_ite_thumb.elf")
        project = angr.Project(path, auto_load_libs=False)
        symbol = project.loader.main_object.get_symbol("loadg_ite_mask")
        assert symbol is not None
        assert symbol.rebased_addr == project.entry == 0x110B5
        assert symbol.size == 16

        block = project.factory.block(symbol.rebased_addr, size=symbol.size, opt_level=1)
        loadgs = [stmt for stmt in block.vex.statements if isinstance(stmt, pyvex.IRStmt.LoadG)]
        assert len(loadgs) == 2
        assert all(stmt.cvt == "ILGop_Ident32" and stmt.end == "Iend_LE" for stmt in loadgs)
        assert isinstance(loadgs[0].addr, pyvex.IRExpr.RdTmp)
        assert isinstance(loadgs[1].addr, pyvex.IRExpr.RdTmp)
        vex_defs = {stmt.tmp: stmt.data for stmt in block.vex.statements if isinstance(stmt, pyvex.IRStmt.WrTmp)}
        second_vex_addr = vex_defs[loadgs[1].addr.tmp]
        assert isinstance(second_vex_addr, pyvex.IRExpr.Binop)
        assert second_vex_addr.op == "Iop_Add32"
        assert second_vex_addr.args[0].tmp == loadgs[0].addr.tmp
        assert isinstance(second_vex_addr.args[1], pyvex.IRExpr.Const)
        assert second_vex_addr.args[1].con.value == 4

        converted = ailment.IRSBConverter.convert(block.vex, ailment.Manager())
        assignments = {
            stmt.dst.tmp_idx: stmt
            for stmt in converted.statements
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.dst, ailment.Expr.Tmp)
        }
        ites: list[Any] = [cast(Any, assignments[stmt.dst].src) for stmt in loadgs]
        assert all(isinstance(expr, ailment.Expr.ITE) for expr in ites)
        assert all(isinstance(expr.iftrue, ailment.Expr.Load) for expr in ites)
        assert all(expr.iftrue.guard is None and expr.iftrue.alt is None for expr in ites)
        assert isinstance(ites[0].iftrue.addr, ailment.Expr.Tmp)
        assert isinstance(ites[1].iftrue.addr, ailment.Expr.Tmp)
        second_ail_addr = assignments[ites[1].iftrue.addr.tmp_idx].src
        assert isinstance(second_ail_addr, ailment.Expr.BinaryOp)
        assert second_ail_addr.op == "Add"
        assert isinstance(second_ail_addr.operands[0], ailment.Expr.Tmp)
        assert second_ail_addr.operands[0].tmp_idx == ites[0].iftrue.addr.tmp_idx
        assert isinstance(second_ail_addr.operands[1], ailment.Expr.Const)
        assert second_ail_addr.operands[1].value == 4

        cfg = project.analyses.CFGFast(normalize=True)
        function = cfg.functions[symbol.rebased_addr]
        assert function is not None
        structurer_option = get_structurer_option()
        assert structurer_option is not None
        for structurer in ("SAILR", "Phoenix"):
            with self.subTest(structurer=structurer):
                dec = project.analyses.Decompiler(
                    function,
                    cfg=cfg.model,
                    options=[(structurer_option, structurer)],
                )
                assert dec.codegen is not None and dec.codegen.text is not None
                print_decompilation_result(dec)

                body = dec.codegen.text[dec.codegen.text.index("{", dec.codegen.text.index("loadg_ite_mask")) + 1 :]
                assert "a1" in body  # the selector still controls which load reaches the mask
                assert body.count("a0") >= 2  # both base and base+4 loads survive
                assert "field_4" in body or "[1]" in body or "+ 4" in body
                assert "field_0" in body or "*a0" in body or "*(a0)" in body or "[0]" in body


if __name__ == "__main__":
    unittest.main()
