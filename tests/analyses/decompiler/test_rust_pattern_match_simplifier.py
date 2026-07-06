#!/usr/bin/env python3
from __future__ import annotations

import unittest

from angr.ailment.expression import BinaryOp, Const, Convert, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.rust.optimization_passes.pre_pattern_match_simplifier import PrePatternMatchSimplifier
from angr.rust.sim_type import RustSimTypeInt, RustSimTypeResult


class TestRustPatternMatchSimplifier(unittest.TestCase):
    """Tests for Rust pattern match simplification."""

    def test_extracts_sign_bit_niche_discriminant(self):
        vvar = VirtualVariable(None, 0, 64, VirtualVariableCategory.STACK, -0x20)
        cast = Convert(None, 64, 64, True, vvar)
        zero = Const(None, 0, 64)
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
                    Const(None, 63, 8),
                ],
                bits=64,
            ),
        )

        scrutinee, discriminant, cmp_op, leftover = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(
            condition
        )

        # Operand access mints a fresh Expression wrapper, so
        # ``assertIs`` cannot discriminate "returned the operand
        # verbatim". Use structural ``.likes()`` -- it ignores ``.idx``
        # mismatches.
        self.assertTrue(scrutinee is not None and scrutinee.likes(vvar))
        self.assertEqual(discriminant, -(1 << 63))
        self.assertEqual(cmp_op, "CmpEQ")
        self.assertIsNone(leftover)

    def test_extracts_truthiness_discriminant(self):
        # `Conv(N -> 1, disc)`, rendered `if result as i8`, means `disc != 0`.
        vvar = VirtualVariable(None, 0, 64, VirtualVariableCategory.STACK, -0x20)
        condition = Convert(None, 64, 1, False, vvar)

        scrutinee, discriminant, cmp_op, leftover = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(
            condition
        )

        self.assertEqual(scrutinee, vvar)
        self.assertEqual(discriminant, 0)
        self.assertEqual(cmp_op, "CmpNE")
        self.assertIsNone(leftover)

    def test_extracts_negated_truthiness_discriminant(self):
        # `Not(Conv(N -> 1, disc))`, rendered `if !(result as i8)`, means `disc == 0`.
        vvar = VirtualVariable(None, 0, 64, VirtualVariableCategory.STACK, -0x20)
        condition = UnaryOp(None, "Not", Convert(None, 64, 1, False, vvar))

        scrutinee, discriminant, cmp_op, leftover = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(
            condition
        )

        self.assertEqual(scrutinee, vvar)
        self.assertEqual(discriminant, 0)
        self.assertEqual(cmp_op, "CmpEQ")
        self.assertIsNone(leftover)

    def test_truthiness_discriminant_preserves_logical_and_leftover(self):
        vvar = VirtualVariable(None, 0, 64, VirtualVariableCategory.STACK, -0x20)
        rest = Const(None, 1, 8)
        condition = BinaryOp(None, "LogicalAnd", [Convert(None, 64, 1, False, vvar), rest], bits=8)

        scrutinee, discriminant, cmp_op, leftover = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(
            condition
        )

        self.assertEqual(scrutinee, vvar)
        self.assertEqual(discriminant, 0)
        self.assertEqual(cmp_op, "CmpNE")
        self.assertEqual(leftover, rest)

    def test_non_boolean_conversion_is_not_a_discriminant(self):
        # A wider truncation (`to_bits != 1`) is an ordinary cast, not a truthiness test.
        vvar = VirtualVariable(None, 0, 64, VirtualVariableCategory.STACK, -0x20)
        condition = Convert(None, 64, 8, False, vvar)

        result = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(condition)

        self.assertEqual(result, (None, None, None, None))

    def test_enum_variant_lookup_matches_signed_and_unsigned_discriminants(self):
        enum_ty = RustSimTypeResult(
            RustSimTypeInt(64, signed=False),
            None,
            0,
            RustSimTypeInt(16, signed=False),
            -(1 << 63),
            8,
        )

        variant = enum_ty.get_variant(1 << 63)
        self.assertIsNotNone(variant)
        assert variant is not None
        self.assertEqual(variant.name, "Err")


if __name__ == "__main__":
    unittest.main()
