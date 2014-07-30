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

