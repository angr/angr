import simuvex
import struct
import logging

l = logging.getLogger(name="procedures.libc_so_6.printf")

######################################
# _printf
######################################

class printf(simuvex.SimProcedure):
	def __init__(self, state, options=[], mode="static"):
		# TODO: Suppress others of using this "state", but use self.initial_state instead
		simuvex.SimProcedure.__init__(self, state, options=options, mode=mode)

		# This function returns
		# Add another exit to the retn_addr that is at the top of the stack now
		retn_addr = self.do_return() # self.initial_state.stack_read_value(0, 8, bp=False)
		# TODO: What if the return address cannot be concretized? Then it won't add any exit there
		self.add_exits(simuvex.s_exit.SimExit(expr = retn_addr, state = state))
		l.debug("Got return address for %s: 0x%08x.", __file__, self._exits[0].concretize())
