#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement


class TestAILSimplifierSwitchHead(unittest.TestCase):
    def test_switch_variable_of_a_lowered_switch_head_is_a_use(self):
        # reaching definitions do not see into IncompleteSwitchCaseHeadStatement (a Python statement), so dead
        # assignment removal must count its switch variable as a use
        manager = Manager()
        vvar = VirtualVariable(manager.next_atom(), 7, 32, VirtualVariableCategory.REGISTER, oident=20)
        switch_variable = BinaryOp(manager.next_atom(), "Add", [vvar, Const(manager.next_atom(), 1, 32)], False)
        head = IncompleteSwitchCaseHeadStatement(manager.next_atom(), switch_variable, [], ins_addr=0x400000)
        block = Block(0x400000, 4, statements=[head])

        assert AILSimplifier._vvars_used_by_switch_heads({(0x400000, None): block}) == {7}
        assert not AILSimplifier._vvars_used_by_switch_heads({(0x400000, None): Block(0x400000, 4, statements=[])})


if __name__ == "__main__":
    unittest.main()
