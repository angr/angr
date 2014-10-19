#!/usr/bin/env python

class SimError(Exception):
    pass

#
# State-related errors
#

class SimStateError(SimError):
    pass

class SimMergeError(SimStateError):
    pass

class SimMemoryError(SimStateError):
    pass

class SimFileError(SimMemoryError):
    pass

#
# Solver-related errors
#

class SimSolverError(SimError):
    pass

class SimValueError(SimSolverError):
    pass

class SimUnsatError(SimValueError):
    pass

#
# SimIROp errors
#

class SimOperationError(SimError):
    pass

class UnsupportedIROpError(SimOperationError):
    pass

#
# SimIRExpr errors
#

class SimExpressionError(SimError):
    pass

class UnsupportedIRExprError(SimExpressionError):
    pass

class SimCCallError(SimExpressionError):
    pass

class UnsupportedCCallError(SimCCallError):
    pass

#
# SimIRStmt errors
#

class SimStatementError(SimError):
    pass

class UnsupportedIRStmtError(SimStatementError):
    pass

class UnsupportedDirtyError(UnsupportedIRStmtError):
    pass

#
# SimIRSB errors
#

class SimRunError(SimError):
    pass

class SimIRSBError(SimRunError):
    pass

class SimProcedureError(SimRunError):
    pass

class SimFastPathError(SimIRSBError):
    pass

class UnsupportedSyscallError(SimProcedureError):
    pass
