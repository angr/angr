import simuvex

import logging
l = logging.getLogger('simuvex.procedures.syscalls')

class exit(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		l.warning("You should be aware that exit() has been called.")
