from ailment.statement import *
from ailment.expression import *


def extract_callee(stmt, kb):
    if isinstance(stmt, Call) and isinstance(stmt.target, Const):
        callee_addr = stmt.target.value
        if callee_addr in kb.functions:
            return kb.functions[callee_addr]
    return None
