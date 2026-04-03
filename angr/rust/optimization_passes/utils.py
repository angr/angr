from __future__ import annotations

import contextlib

from angr import ailment
from angr.ailment import Block, AILBlockRewriter
from angr.ailment.statement import Label, Jump, SideEffectStatement, Statement
from angr.ailment.expression import Const, Call


def extract_callee(obj, kb):
    if isinstance(obj, ailment.Block) and obj.statements:
        for stmt in reversed(obj.statements):
            if isinstance(stmt, Call):
                return extract_callee(stmt, kb)
            if not isinstance(stmt, Label) or not isinstance(stmt, Jump):
                break
    if isinstance(obj, Call) and isinstance(obj.target, Const):
        callee_addr = obj.target.value
        if callee_addr in kb.functions:
            return kb.functions[callee_addr]
    return None


def extract_str(project, str_ptr, str_len):
    """
    Extract Rust string literal with given ptr and len
    """
    decoded_str = None
    if str_len == 0:
        return ""
    memory = project.loader.memory
    if str_ptr >= 0 and (
        (section := project.loader.find_section_containing(str_ptr)) and section.is_readable and not section.is_writable
    ):
        with contextlib.suppress(UnicodeDecodeError):
            decoded_str = memory.load(str_ptr, str_len).decode("utf-8")
            # decoded_str = decoded_str if decoded_str.replace(
            #     "\n", "").replace("\t", "").replace("\r", "").isprintable() else None
    return decoded_str


def extract_str_from_addr(project, addr):
    memory = project.loader.memory
    if addr >= 0 and ((section := project.loader.find_section_containing(addr)) and section.is_readable):
        try:
            str_ptr = memory.unpack(addr, project.arch.struct_fmt())[0]
            str_len = memory.unpack(addr + project.arch.bytes, project.arch.struct_fmt())[0]
            return extract_str(project, str_ptr, str_len)
        except KeyError:
            return None
    return None


class SideEffectStatementRewriter(AILBlockRewriter):
    """Rewrite SideEffectStatement nodes via a callback."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def _handle_SideEffectStatement(self, stmt_idx: int, stmt: SideEffectStatement, block: Block | None):
        new_stmt = self.callback(stmt, block, stmt)
        if new_stmt:
            block.statements[stmt_idx] = new_stmt
        return new_stmt


class CallRewriter(AILBlockRewriter):
    """Rewrite Call expressions and SideEffectStatements via a callback."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        new_stmt = self.callback(expr, block, stmt)
        if new_stmt:
            block.statements[stmt_idx] = new_stmt
        return new_stmt


def replace_argument_pairs(call: Call, callback) -> Call:
    if not call.args:
        return call
    queue = list(call.args)
    new_args = []
    changed = False
    while len(queue) > 1:
        arg = queue.pop(0)
        next_arg = queue.pop(0)
        replaced, replacement = callback(arg, next_arg)
        if replaced:
            new_args.extend(replacement)
            changed = True
        else:
            new_args.append(arg)
            queue.insert(0, next_arg)
    if changed:
        new_args.extend(queue)
        new_call = call.copy()
        new_call.args = new_args
        return new_call
    return call
