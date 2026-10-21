#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import itertools
import unittest

import angr
from angr import ailment, claripy
from angr.ailment.expression import BinaryOp, Const, Convert
from angr.ailment.manager import Manager
from angr.ailment.statement import ConditionalJump
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.peephole_optimizations import CmpORDRewriter
from angr.rustylib.ailment import VEXIRSBConverter


class TestCmpORDRewriter(unittest.TestCase):
    def test_comparison_semantics(self):
        project = angr.load_shellcode(b"\x60\x00\x00\x00", "ppc")
        manager = Manager()
        opt = CmpORDRewriter(project, project.kb, manager)
        processor = ConditionProcessor(project.arch, manager)
        for mask, signed, wrapper, outer, xor, value in itertools.product(
            (2, 4, 8),
            (False, True),
            ("bare", "convert", "mask", "nested"),
            ("CmpEQ", "CmpNE"),
            (False, True),
            (9, 10, 11, -1),
        ):
            with self.subTest(mask=mask, signed=signed, wrapper=wrapper, outer=outer, xor=xor, value=value):
                compare = BinaryOp(
                    manager.next_atom(),
                    "CmpORD",
                    [Const(manager.next_atom(), value & 0xFFFFFFFF, 32), Const(manager.next_atom(), 10, 32)],
                    signed,
                    ins_addr=0x1000,
                )
                operand = compare
                if wrapper in {"convert", "nested"}:
                    operand = Convert(manager.next_atom(), 32, 8, False, operand)
                if wrapper == "nested":
                    operand = Convert(manager.next_atom(), 8, 32, False, operand)
                if wrapper in {"mask", "nested"}:
                    operand = BinaryOp(manager.next_atom(), "And", [operand, Const(manager.next_atom(), 255, 32)])
                condition = BinaryOp(
                    manager.next_atom(), "And", [operand, Const(manager.next_atom(), mask, operand.bits)]
                )
                if xor:
                    condition = BinaryOp(
                        manager.next_atom(), "Xor", [condition, Const(manager.next_atom(), mask, condition.bits)]
                    )
                condition = BinaryOp(
                    manager.next_atom(), outer, [condition, Const(manager.next_atom(), 0, condition.bits)], bits=1
                )
                stmt = ConditionalJump(
                    0,
                    condition,
                    Const(None, 0x1010, 32),
                    Const(None, 0x1020, 32),
                    true_target_idx=1,
                    false_target_idx=2,
                    ins_addr=0x1004,
                )
                result = opt.optimize(stmt, 0, None)
                assert result is not None
                assert result.condition.bits == 1
                assert result.condition.signed == signed
                assert result.condition.operands == compare.operands
                assert result.condition.tags == compare.tags
                assert result.tags == stmt.tags
                assert (result.true_target, result.false_target) == (stmt.true_target, stmt.false_target)
                assert (result.true_target_idx, result.false_target_idx) == (1, 2)
                lhs = value if signed else value & 0xFFFFFFFF
                field = 2 if lhs == 10 else 8 if lhs < 10 else 4
                expected = bool(field & mask) ^ xor ^ (outer == "CmpEQ")
                actual = processor.claripy_ast_from_ail_condition(result.condition)
                assert claripy.is_true(claripy.simplify(actual)) == expected

    def test_destructive_wrappers_are_not_removed(self):
        manager = Manager()
        opt = CmpORDRewriter(None, None, manager)
        compare = BinaryOp(None, "CmpORD", [Const(None, 11, 32), Const(None, 10, 32)], True)
        for operand, mask in (
            (Convert(None, 32, 2, False, compare), 4),
            (Convert(None, 3, 32, True, Convert(None, 32, 3, False, compare)), 8),
            (BinaryOp(None, "And", [compare, Const(None, 2, 32)]), 4),
            (Convert(None, 32, 32, False, compare, from_type=Convert.TYPE_FP), 4),
        ):
            with self.subTest(operand=operand, mask=mask):
                condition = BinaryOp(None, "And", [operand, Const(None, mask, operand.bits)])
                condition = BinaryOp(None, "CmpNE", [condition, Const(None, 0, condition.bits)])
                stmt = ConditionalJump(0, condition, Const(None, 0x1010, 32), Const(None, 0x1020, 32))
                assert opt.optimize(stmt, 0, None) is None

    def test_vex_comparison_signedness(self):
        for arch, encoding, bits, signed in (
            ("ppc", "2c03000a", 32, True),
            ("ppc", "2803000a", 32, False),
            ("ppc64", "2c23000a", 64, True),
            ("ppc64", "2823000a", 64, False),
        ):
            with self.subTest(arch=arch, signed=signed):
                data = bytes.fromhex(encoding + "41810008")  # compare r3, 10; bgt
                project = angr.load_shellcode(data, arch, load_address=0x1000)
                irsb = project.factory.block(0x1000, opt_level=1).vex
                from_py = VEXIRSBConverter.convert(irsb, Manager())
                from_lift = VEXIRSBConverter.convert_from_lift(project.arch, 0x1000, data, Manager(), opt_level=1)
                assert from_py == from_lift
                compare = next(
                    stmt.src
                    for stmt in from_py.statements
                    if isinstance(stmt, ailment.Stmt.Assignment)
                    and isinstance(stmt.src, BinaryOp)
                    and stmt.src.op == "CmpORD"
                )
                assert compare.signed == signed
                assert compare.operands[0].bits == bits

    def test_decompile_comparison(self):
        # cmpwi r3, 10; ble false; li r3, 1; blr; false: li r3, 0; blr
        data = bytes.fromhex("2c03000a4081000c386000014e800020386000004e800020")
        project = angr.load_shellcode(data, "ppc", load_address=0x1000)
        cfg = project.analyses.CFGFast(normalize=True)
        for flavor in ("pseudocode", "rust"):
            with self.subTest(flavor=flavor):
                dec = project.analyses.Decompiler(cfg.kb.functions[0x1000], cfg=cfg.model, flavor=flavor)
                assert dec.codegen is not None and dec.codegen.text is not None
                assert "CmpORD" not in dec.codegen.text
                self.assertRegex(dec.codegen.text, r"(?:<=|>)\s*10|(?:<|>=)\s*11")


if __name__ == "__main__":
    unittest.main()
