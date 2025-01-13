from __future__ import annotations

import logging

from .assign import SimSootStmt_Assign
from .return_ import SimSootStmt_Return, SimSootStmt_ReturnVoid
from .identity import SimSootStmt_Identity
from .goto import SimSootStmt_Goto
from .invoke import SimSootStmt_Invoke
from .if_ import SimSootStmt_If
from .switch import SimSootStmt_TableSwitch, SimSootStmt_LookupSwitch
from .throw import SimSootStmt_Throw

l = logging.getLogger("angr.engines.soot.statements")


def translate_stmt(stmt, state):
    stmt_name = stmt.__class__.__name__.split(".")[-1]
    stmt_name = stmt_name.removesuffix("Stmt")

    stmt_cls_name = f"SimSootStmt_{stmt_name}"
    if stmt_cls_name in globals():
        stmt_class = globals()[stmt_cls_name]
        s = stmt_class(stmt, state)
        s.process()
        return s

    l.warning("Unsupported Soot statement %s.", stmt_cls_name)
    return None


__all__ = (
    "SimSootStmt_Assign",
    "SimSootStmt_Goto",
    "SimSootStmt_Identity",
    "SimSootStmt_If",
    "SimSootStmt_Invoke",
    "SimSootStmt_LookupSwitch",
    "SimSootStmt_Return",
    "SimSootStmt_ReturnVoid",
    "SimSootStmt_TableSwitch",
    "SimSootStmt_Throw",
    "translate_stmt",
)
