from ....errors import UnsupportedIRStmtError, UnsupportedDirtyError, SimStatementError
from .... import sim_options as o

from .base import SimIRStmt
from .noop import SimIRStmt_NoOp
from .imark import SimIRStmt_IMark
from .abihint import SimIRStmt_AbiHint
from .wrtmp import SimIRStmt_WrTmp
from .put import SimIRStmt_Put
from .store import SimIRStmt_Store
from .mbe import SimIRStmt_MBE
from .dirty import SimIRStmt_Dirty
from .exit import SimIRStmt_Exit
from .cas import SimIRStmt_CAS
from .storeg import SimIRStmt_StoreG
from .loadg import SimIRStmt_LoadG
from .llsc import SimIRStmt_LLSC
from .puti import SimIRStmt_PutI

import logging
l = logging.getLogger(name=__name__)

def translate_stmt(stmt, state):
    """
    Executes a VEX statement against a state
    :param stmt:
    :param state:
    :return:
    """
    try:
        stmt_class = STMT_CLASSES[stmt.tag_int]
    except IndexError:
        l.error("Unsupported statement type %s", (type(stmt)))
        if o.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
            raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
        state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')
        return None
    else:
        s = stmt_class(stmt, state)
        s.process()
        return s

import pyvex

STMT_CLASSES = [None]*pyvex.stmt.tag_count
for name, cls in vars(pyvex.stmt).items():
    if isinstance(cls, type) and issubclass(cls, pyvex.stmt.IRStmt) and cls is not pyvex.stmt.IRStmt:
        STMT_CLASSES[cls.tag_int] = globals()['SimIRStmt_' + name]
if any(x is None for x in STMT_CLASSES):
    raise ImportError("Something is messed up loading angr: not all pyvex stmts accounted for")
