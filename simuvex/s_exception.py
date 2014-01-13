#!/usr/bin/env python

class SimError(Exception):
	pass

class SimModeError(SimError):
	pass

class SimProcedureError(Exception):
	pass

class SimMergeError(Exception):
	pass
