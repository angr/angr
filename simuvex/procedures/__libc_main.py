import simuvex

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
			buff_rcx = self.initial_state.registers.read_from(72, 8, True)[::-1]
			rcx = struct.unpack("<Q", buff_rcx)[0]

			# TODO: address from
			#self.add_refs(SimCodeRef(0, 0,

	def exits(self):
		pass
