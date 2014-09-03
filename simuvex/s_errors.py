#!/usr/bin/env python

class SimError(Exception):
	pass

class SimIRSBError(SimError):
	pass

class SimModeError(SimError):
	pass

class SimProcedureError(SimError):
	pass

class SimMergeError(SimError):
	pass

class SimValueError(SimError):
	pass

class SimUnsatError(SimValueError):
	pass

class SimMemoryError(SimError):
	pass

class UnsupportedIRExprError(SimError):
	pass

class UnsupportedIRStmtError(SimError):
	pass

class UnsupportedDirtyError(SimError):
	pass

class UnsupportedCCallError(SimError):
	pass

class UnsupportedSyscallError(SimError):
	pass

class UnsupportedIROpError(SimError):
	pass

class SimCCallError(SimError):
	pass
