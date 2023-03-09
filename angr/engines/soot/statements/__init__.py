import logging

from .assign import SimSootStmt_Assign
from .goto import SimSootStmt_Goto
from .identity import SimSootStmt_Identity
from .if_ import SimSootStmt_If
from .invoke import SimSootStmt_Invoke
from .return_ import SimSootStmt_Return, SimSootStmt_ReturnVoid
from .switch import SimSootStmt_LookupSwitch, SimSootStmt_TableSwitch
from .throw import SimSootStmt_Throw

l = logging.getLogger("angr.engines.soot.statements")


def translate_stmt(stmt, state):
    stmt_name = stmt.__class__.__name__.split(".")[-1]
    if stmt_name.endswith("Stmt"):
        stmt_name = stmt_name[:-4]

    stmt_cls_name = "SimSootStmt_%s" % stmt_name
    if stmt_cls_name in globals():
        stmt_class = globals()[stmt_cls_name]
        s = stmt_class(stmt, state)
        s.process()
        return s

    else:
        l.warning("Unsupported Soot statement %s.", stmt_cls_name)
        return None
