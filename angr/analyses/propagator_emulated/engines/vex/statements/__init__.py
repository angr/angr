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

import pyvex

STMT_CLASSES = [None]*pyvex.stmt.tag_count
for name, cls in vars(pyvex.stmt).items():
    if isinstance(cls, type) and issubclass(cls, pyvex.stmt.IRStmt) and cls is not pyvex.stmt.IRStmt:
        STMT_CLASSES[cls.tag_int] = globals()['SimIRStmt_' + name]
if any(x is None for x in STMT_CLASSES):
    raise ImportError("Something is messed up loading angr: not all pyvex stmts accounted for")
