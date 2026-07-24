# pylint: disable=protected-access
from __future__ import annotations

from types import SimpleNamespace

from angr.ailment import Block
from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import ConditionalJump, Return
from angr.analyses.decompiler.ssailification.rewriting import RewritingAnalysis
from angr.analyses.decompiler.ssailification.rewriting_engine import SimEngineSSARewriting
from angr.utils.ail import is_head_controlled_loop_block


def test_stack_predicate_without_head_controlled_loop_outstate():
    jump = ConditionalJump(0, Const(1, 1, 1), Const(2, 0x4002, 64), None)
    block = Block(
        0x4000,
        4,
        statements=[
            jump,
            Return(3, []),
        ],
    )
    assert is_head_controlled_loop_block(block)
    assert not SimEngineSSARewriting._is_head_controlled_loop_jump(block, jump)

    stack_vvar = VirtualVariable(4, 1, 32, VirtualVariableCategory.STACK, oident=-8)
    rewriting = object.__new__(RewritingAnalysis)
    rewriting._ail_manager = Manager()
    rewriting.head_controlled_loop_outstates = {}
    rewriting.out_states = {(block.addr, block.idx): SimpleNamespace(stackvars={-8: stack_vvar})}

    stop, result = rewriting._stack_predicate(block, stack_offset=-8)

    assert stop
    assert result is not None and result is not stack_vvar and result.likes(stack_vvar)
