#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace
from typing import cast

import archinfo

from angr.ailment.expression import (
    BinaryOp,
    Const,
    Expression,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.analyses.decompiler.optimization_passes.win_stack_canary_simplifier import WinStackCanarySimplifier

INT32 = range(-(1 << 31), 1 << 31)


def bp_offset(arch, bp_before: int, expr: Expression, ins_addr: int = 0x401000) -> int | None:
    """``_get_bp_offset`` with the only two attributes it reads.

    Building a real pass means building a function graph and running it, while the method itself
    only reads ``project.arch`` and asks the stack-pointer tracker for one offset.
    """
    reader = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        _stack_pointer_tracker=SimpleNamespace(offset_before=lambda _addr, _reg: bp_before),
    )
    return WinStackCanarySimplifier._get_bp_offset(cast(WinStackCanarySimplifier, reader), expr, ins_addr)


def frame_pointer(arch) -> Expression:
    return VirtualVariable(0, 1, arch.bits, VirtualVariableCategory.REGISTER, oident=arch.bp_offset)


def minus(arch, amount: int) -> Expression:
    return BinaryOp(0, "Sub", [frame_pointer(arch), Const(1, amount, arch.bits)], False)


class TestWinStackCanarySimplifier(unittest.TestCase):
    def test_bp_relative_canary_slot_is_signed(self):
        # MSVC stores the cookie through the frame pointer when the stack-pointer tracker could not
        # rewrite it into a StackBaseOffset. The slot is a signed stack offset: it keys
        # Clinic.stack_items, whose protobuf map is int32, and the pass compares it against
        # StackBaseOffset.offset, which ailment normalises to signed.
        for arch, bp_before, amount, expected in (
            (archinfo.ArchX86(), -8, 8, -16),
            (archinfo.ArchX86(), -12, 4, -16),
            (archinfo.ArchAMD64(), -16, 0x28, -56),
        ):
            offset = bp_offset(arch, bp_before, minus(arch, amount))
            assert offset == expected, f"{arch.name}: {offset} != {expected}"
            assert offset in INT32

    def test_bp_relative_offset_still_wraps_to_the_architecture_width(self):
        # `ebp - 0xfffffff0` is `ebp + 16`; the subtraction has to wrap at the register width
        # before it is read as signed, or the offset comes out four billion below the frame.
        arch = archinfo.ArchX86()
        assert bp_offset(arch, -8, minus(arch, 0xFFFFFFF0)) == 8

    def test_the_trackers_unsigned_answer_is_read_as_signed(self):
        # StackPointerTracker.offset_before answers with the unsigned register value: on a 32-bit
        # frame four bytes below the base it returns 4294967292, not -4.
        arch = archinfo.ArchX86()
        assert bp_offset(arch, 0xFFFFFFFC, frame_pointer(arch)) == -4
        assert bp_offset(arch, -4, frame_pointer(arch)) == -4

    def test_the_three_forms_agree(self):
        # The caller compares one form's answer against another's, so a slot spelled three ways has
        # to give one offset.
        arch = archinfo.ArchX86()
        direct = bp_offset(arch, 0, StackBaseOffset(0, arch.bits, -16))
        through_tracker = bp_offset(arch, -16, frame_pointer(arch))
        through_subtraction = bp_offset(arch, -8, minus(arch, 8))
        assert direct == through_tracker == through_subtraction == -16

    def test_an_unrecognised_expression_is_not_an_offset(self):
        arch = archinfo.ArchX86()
        assert bp_offset(arch, -8, Const(0, 8, arch.bits)) is None


if __name__ == "__main__":
    unittest.main()
