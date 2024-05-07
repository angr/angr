import ailment
from ailment.statement import *
from ailment.expression import *

from ...utils.library import get_rust_function_name


def extract_callee(obj, kb):
    if isinstance(obj, ailment.Block) and obj.statements:
        return extract_callee(obj.statements[-1], kb)
    if isinstance(obj, Call) and isinstance(obj.target, Const):
        callee_addr = obj.target.value
        if callee_addr in kb.functions:
            return kb.functions[callee_addr]
    return None


def extract_rust_function_name(func):
    if func and func.demangled_name:
        return get_rust_function_name(func.demangled_name)
    return None


def extract_value(expr):
    if isinstance(expr, ailment.expression.Const):
        return expr.value
    return None


def remove_branch(block: ailment.Block, removed_branch: int):
    if len(block.statements) >= 1 and isinstance(block.statements[-1], ConditionalJump):
        jmp = block.statements[-1]
        if isinstance(jmp.true_target, Const) and jmp.true_target.value == removed_branch:
            jmp = Jump(jmp.idx, jmp.false_target, ins_addr=jmp.ins_addr)
        elif isinstance(jmp.false_target, Const) and jmp.false_target.value == removed_branch:
            jmp = Jump(jmp.idx, jmp.true_target, ins_addr=jmp.ins_addr)
        block.statements[-1] = jmp
