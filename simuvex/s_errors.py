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

class SimMemoryLimitError(SimMemoryError):
    pass

class SimMemoryAddressError(SimMemoryError):
    pass

class SimEventError(SimStateError):
    pass

class SimFileError(SimMemoryError):
    pass

class SimPosixError(SimStateError):
    pass

#
# Solver-related errors
#

class SimSolverError(SimError):
    pass

class SimSolverModeError(SimSolverError):
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

class SimUninitializedAccessError(SimExpressionError):
    def __init__(self, expr_type, expr):
        self.expr_type = expr_type
        self.expr = expr

    def __repr__(self):
        return "SimUninitializedAccessError (expr %s is used as %s)" % (self.expr, self.expr_type)

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

#
# SimSlicer errors
#

class SimSlicerError(SimError):
    pass

#
# SimAction errors
#

class SimActionError(SimError):
    pass

#
# SimCC errors
#

class SimCCError(SimError):
    pass
