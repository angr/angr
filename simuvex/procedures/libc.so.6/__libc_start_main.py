import simuvex
import symexec

######################################
# __libc_start_main
######################################

import struct

class __libc_start_main(simuvex.SimProcedure):
	def __init__(self, state, options=None, mode=None):
		simuvex.SimProcedure.__init__(self, options=options, mode=mode)

		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
		if isinstance(self.initial_state.arch, simuvex.SimAMD64):
			# Get main pc from registers
			rcx_val = self.initial_state.registers.read_from(72, 8)
			rcx_val = simuvex.s_helpers.fix_endian(self.initial_state.arch.endness,
										  rcx_val)
			main_addr = simuvex.SimValue(rcx_val)
			self.add_exits(simuvex.s_exit.SimExit(rcx_val))

			# TODO: address from
			# TODO: What should we do for the addr parameter?
			self.add_refs(simuvex.SimCodeRef(-1, -1, main_addr, None, None))
		else:
			raise Exception("Architecture %s is not supported yet." % self.initial_state.arch)
