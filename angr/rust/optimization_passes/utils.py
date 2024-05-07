import ailment
import networkx
from ailment.statement import *
from ailment.expression import *

from angr.analyses.decompiler.ailgraph_walker import RemoveNodeNotice, AILGraphWalker


def extract_callee(stmt, kb):
    if isinstance(stmt, Call) and isinstance(stmt.target, Const):
        callee_addr = stmt.target.value
        if callee_addr in kb.functions:
            return kb.functions[callee_addr]
    return None


def remove_branch(block: ailment.Block, removed_branch: int):
    if len(block.statements) >= 1 and isinstance(block.statements[-1], ConditionalJump):
        jmp = block.statements[-1]
        if isinstance(jmp.true_target, Const) and jmp.true_target.value == removed_branch:
            jmp = Jump(jmp.idx, jmp.false_target, ins_addr=jmp.ins_addr)
        elif isinstance(jmp.false_target, Const) and jmp.false_target.value == removed_branch:
            jmp = Jump(jmp.idx, jmp.true_target, ins_addr=jmp.ins_addr)
        block.statements[-1] = jmp
