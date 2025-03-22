import ailment
from ailment import AILBlockWalker, Block
from ailment.statement import *
from ailment.expression import *


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
    memory = project.loader.memory
    if str_ptr >= 0 and (
        (section := project.loader.find_section_containing(str_ptr)) and section.is_readable and not section.is_writable
    ):
        try:
            decoded_str = memory.load(str_ptr, str_len).decode("utf-8")
            decoded_str = (
                decoded_str if decoded_str.replace("\n", "").replace("\t", "").replace("\r", "").isprintable() else None
            )
        except UnicodeDecodeError:
            pass
    return decoded_str


def extract_str_from_addr(project, addr):
    memory = project.loader.memory
    if addr >= 0 and ((section := project.loader.find_section_containing(addr)) and section.is_readable):
        str_ptr = memory.unpack(addr, project.arch.struct_fmt())[0]
        str_len = memory.unpack(addr + project.arch.bytes, project.arch.struct_fmt())[0]
        return extract_str(project, str_ptr, str_len)
    return None


class CallReplacer(AILBlockWalker):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        if block is None:
            return None
        new_stmt = self.callback(stmt, block, is_expr=False)
        if new_stmt:
            block.statements[stmt_idx] = new_stmt
        return new_stmt

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        return self.callback(expr, block, is_expr=True)
