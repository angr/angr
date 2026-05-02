#!/usr/bin/env python3
from __future__ import annotations

import unittest

from angr.ailment.expression import BinaryOp, Const, Convert, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.rust.optimization_passes.pre_pattern_match_simplifier import PrePatternMatchSimplifier
from angr.rust.sim_type import RustSimTypeInt, RustSimTypeResult


class TestRustPatternMatchSimplifier(unittest.TestCase):
    def test_extracts_sign_bit_niche_discriminant(self):
        vvar = VirtualVariable(None, 0, 64, VirtualVariableCategory.STACK, -0x20)
        cast = Convert(None, 64, 64, True, vvar)
        zero = Const(None, None, 0, 64)
        condition = Convert(
            None,
            64,
            8,
            False,
            BinaryOp(
                None,
                "Shr",
                [
                    BinaryOp(
                        None,
                        "And",
                        [
                            BinaryOp(None, "Xor", [zero, cast], bits=64),
                            BinaryOp(None, "Xor", [zero, UnaryOp(None, "Neg", cast)], bits=64),
                        ],
                        bits=64,
                    ),
                    Const(None, None, 63, 8),
                ],
                bits=64,
            ),
        )

        scrutinee, discriminant, cmp_op, leftover = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(
            condition
        )

        self.assertIs(scrutinee, vvar)
        self.assertEqual(discriminant, -(1 << 63))
        self.assertEqual(cmp_op, "CmpEQ")
        self.assertIsNone(leftover)

    def test_enum_variant_lookup_matches_signed_and_unsigned_discriminants(self):
        enum_ty = RustSimTypeResult(
            RustSimTypeInt(64, signed=False),
            None,
            0,
            RustSimTypeInt(16, signed=False),
            -(1 << 63),
            8,
        )

        self.assertEqual(enum_ty.get_variant(1 << 63).name, "Err")


if __name__ == "__main__":
    unittest.main()
