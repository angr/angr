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
