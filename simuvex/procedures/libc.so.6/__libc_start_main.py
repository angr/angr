import simuvex
import symexec

######################################
# __libc_start_main
######################################

import struct

class __libc_start_main(simuvex.SimProcedure):
	def __init__(self, state, options=[], mode="static"):
		simuvex.SimProcedure.__init__(self, state, options=options, mode=mode)

		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
		if isinstance(self.initial_state.arch, simuvex.SimAMD64):
			# Get main pc from registers
			rdi_val = self.initial_state.registers.read_from(72, 8)
			main_addr = simuvex.SimValue(rdi_val)
			self.add_exits(simuvex.s_exit.SimExit(expr = main_addr.expr, state = state))

			# TODO: address from
			# TODO: What should we do for the addr parameter?
			self.add_refs(simuvex.SimCodeRef(-1, -1, main_addr, [ ], [ ]))
		else:
			raise Exception("Architecture %s is not supported yet." % self.initial_state.arch)
