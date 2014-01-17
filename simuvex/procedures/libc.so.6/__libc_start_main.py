import simuvex

######################################
# __libc_start_main
######################################
class __libc_start_main(simuvex.SimProcedure):
	def __init__(self):
		# TODO: handle symbolic and static modes

		# Get main pc from registers
		main_addr = self.get_arg_value(0)
		self.add_exits(simuvex.s_exit.SimExit(expr=main_addr.expr, state=self.state))

		self.add_refs(simuvex.SimCodeRef(self.addr_from, self.stmt_from, main_addr, [], []))
