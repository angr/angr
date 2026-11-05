#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import Call, Const, VEXCCallExpression, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return, Store
from angr.knowledge_plugins.functions import Function


class TestFoldCallIntoFlagsThunk(unittest.TestCase):
    """newstar_infect_vmp: `eax = FindNextFileW(); flags = eflags_all(LOGICL, eax, 0, 0)` keeps eax a variable."""

    def _simplify(self, callee):
        proj = angr.load_shellcode(b"\xc3", "X86")
        eax = proj.arch.registers["eax"][0]
        ret = VirtualVariable(1, 1, 32, VirtualVariableCategory.REGISTER, oident=eax)
        flags = VirtualVariable(2, 2, 32, VirtualVariableCategory.REGISTER, oident=proj.arch.registers["ecx"][0])
        # LOGICL thunk of the call result; calculate_condition also takes a condition code (5: not zero)
        operands = [Const(4, 15, 32), VirtualVariable(5, 1, 32, VirtualVariableCategory.REGISTER, oident=eax),
                    Const(6, 0, 32), Const(7, 0, 32)]
        if callee.endswith("condition"):
            operands.insert(0, Const(12, 5, 32))
        thunk = VEXCCallExpression(3, callee, operands, bits=32)
        stmts = [
            Assignment(0, ret, Call(8, Const(9, 0x401100, 32), args=[], bits=32), ins_addr=0x401000),
            Assignment(1, flags, thunk, ins_addr=0x401005),
            Store(2, Const(10, 0x500000, 32), VirtualVariable(11, 2, 32, VirtualVariableCategory.REGISTER,
                                                              oident=flags.oident), 4, "Iend_LE", ins_addr=0x401008),
            Return(3, [], ins_addr=0x40100C),
        ]
        graph = networkx.DiGraph()
        graph.add_node(Block(0x401000, 0x10, statements=stmts, idx=0))
        simp = proj.analyses.AILSimplifier(
            Function(proj.kb.functions, 0x401000), func_graph=graph, ail_manager=ailment.Manager(),
            remove_dead_memdefs=False, unify_variables=True,
        )
        return next(iter(simp.func_graph)).statements

    def test_call_result_stays_out_of_the_flags_thunk(self):
        for callee in ("x86g_calculate_eflags_all", "x86g_calculate_condition"):
            stmts = self._simplify(callee)
            thunks = [s for s in stmts if isinstance(s, Assignment) and isinstance(s.src, VEXCCallExpression)]
            assert thunks, stmts
            assert not any(isinstance(op, Call) for op in thunks[0].src.operands), (callee, thunks[0])
            assert any(isinstance(s, Assignment) and isinstance(s.src, Call) for s in stmts), stmts


if __name__ == "__main__":
    unittest.main()
