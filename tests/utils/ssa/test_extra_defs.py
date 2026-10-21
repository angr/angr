from __future__ import annotations

import unittest

from angr.ailment import Block, Const
from angr.ailment.expression import Call, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, SideEffectStatement
from angr.utils.ssa import get_uses_defs, get_vvar_deflocs


def _stack_vvar(varid: int) -> VirtualVariable:
    return VirtualVariable(varid, varid, 64, VirtualVariableCategory.STACK, oident=-0x20)


def _call_block(addr: int, extra_def: bool, tag: list[int]) -> Block:
    ref = UnaryOp(0, "Reference", _stack_vvar(7), bits=64)
    if extra_def:
        ref.tags["extra_def"] = True
    call = Call(1, "callee", args=[ref])
    stmt = SideEffectStatement(2, call, ins_addr=addr, extra_defs=tag)
    return Block(addr, 1, statements=[stmt], idx=0)


class TestExtraDefsTag(unittest.TestCase):
    """A statement's extra_defs tag must be backed by extra_def References inside that same statement."""

    def test_matching_tag(self):
        block = _call_block(0x1000, True, [7])
        deflocs = get_vvar_deflocs([block])
        self.assertEqual(deflocs[7][1].block_addr, 0x1000)
        vvar_deflocs, _, _, _ = get_uses_defs([block])
        self.assertIn(7, vvar_deflocs)

    def test_stale_tag_is_rejected(self):
        # the tag survived a rewrite that dropped the Reference; the vvar is still defined by another block, which
        # must not mask the stale tag
        other = Block(0x2000, 1, statements=[Assignment(0, _stack_vvar(7), Const(1, 0, 64), ins_addr=0x2000)], idx=0)
        stale = _call_block(0x1000, False, [7])
        with self.assertRaises(AssertionError):
            get_vvar_deflocs([stale])
        with self.assertRaises(AssertionError):
            get_vvar_deflocs([stale, other])
        with self.assertRaises(AssertionError):
            get_uses_defs([stale])


if __name__ == "__main__":
    unittest.main()
