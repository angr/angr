import simuvex

######################################
# __isoc99_scanf
######################################

class __isoc99_scanf(simuvex.SimProcedure):
	def __init__(self):
		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
		if isinstance(self.state.arch, simuvex.SimAMD64):
			retn_addr = self.do_return()
			self.add_exits(simuvex.s_exit.SimExit(expr=retn_addr, state=self.state))
		else:
			raise Exception("Architecture %s is not supported yet." % self.state.arch)
