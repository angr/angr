#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.block import Block
from angr.ailment.expression import Const, Phi, Tmp, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.block_simplifier import AILCodeLocation, BlockSimplifier


class TestBlockSimplifierPhiCollapse(unittest.TestCase):
    """A Phi assignment collapses to a constant only when every source is replaced by that constant."""

    def _case(self, manager: Manager):
        def vvar(varid: int) -> VirtualVariable:
            return VirtualVariable(manager.next_atom(), varid, 32, VirtualVariableCategory.REGISTER, 8)

        srcs = [vvar(72), vvar(52), vvar(63)]
        phi = Phi(manager.next_atom(), 32, [((0x41EAC3 + i, None), v) for i, v in enumerate(srcs)])
        phi_stmt = Assignment(manager.next_atom(), vvar(15), phi, ins_addr=0x41EAC3)
        tmp = Tmp(manager.next_atom(), 21, 32)
        tmp_stmt = Assignment(manager.next_atom(), vvar(99), tmp, ins_addr=0x41EAC3)
        block = Block(0x41EAC3, 8, statements=[phi_stmt, tmp_stmt])
        return block, srcs, tmp

    def test_a_partially_replaced_phi_is_left_alone(self):
        manager = Manager()
        block, srcs, tmp = self._case(manager)
        zero = Const(manager.next_atom(), 0, 32)
        replacements = {
            AILCodeLocation(0x41EAC3, None, 0): {srcs[0]: zero},
            # a non-vvar replacement on a later statement must not confuse the Phi check
            AILCodeLocation(0x41EAC3, None, 1): {tmp: zero},
        }
        _, new_block = BlockSimplifier.replace_and_build(block, replacements, manager)
        assert isinstance(new_block.statements[0].src, Phi)
        assert isinstance(new_block.statements[1].src, Const)

    def test_a_fully_replaced_phi_collapses_to_the_constant(self):
        manager = Manager()
        block, srcs, tmp = self._case(manager)
        zero = Const(manager.next_atom(), 0, 32)
        replacements = {
            AILCodeLocation(0x41EAC3, None, 0): {v: zero for v in srcs},
            AILCodeLocation(0x41EAC3, None, 1): {tmp: zero},
        }
        changed, new_block = BlockSimplifier.replace_and_build(block, replacements, manager)
        assert changed
        src = new_block.statements[0].src
        assert isinstance(src, Const) and src.value == 0

    def test_different_constants_do_not_collapse(self):
        manager = Manager()
        block, srcs, _ = self._case(manager)
        consts = [Const(manager.next_atom(), i, 32) for i in range(3)]
        replacements = {AILCodeLocation(0x41EAC3, None, 0): dict(zip(srcs, consts))}
        _, new_block = BlockSimplifier.replace_and_build(block, replacements, manager)
        assert isinstance(new_block.statements[0].src, Phi)


if __name__ == "__main__":
    unittest.main()
