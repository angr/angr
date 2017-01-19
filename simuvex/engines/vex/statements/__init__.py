from simuvex.s_errors import UnsupportedIRStmtError, UnsupportedDirtyError, SimStatementError
from simuvex import s_options as o

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
l = logging.getLogger('simuvex.vex.statements')

def translate_stmt(stmt, state):
    stmt_name = 'SimIRStmt_' +  type(stmt).__name__.split('IRStmt')[-1].split('.')[-1]

    if stmt_name in globals():
        stmt_class = globals()[stmt_name]
        s = stmt_class(stmt, state)
        s.process()
        return s
    else:
        l.error("Unsupported statement type %s", (type(stmt)))
        if o.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
            raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
        state.log.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')
