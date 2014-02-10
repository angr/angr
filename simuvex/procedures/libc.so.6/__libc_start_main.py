import simuvex

######################################
# __libc_start_main
######################################
class __libc_start_main(simuvex.SimProcedure):
	def __init__(self):
		# TODO: handle symbolic and static modes

		if self.state.arch.name == "PPC32":
			# for some dumb reason, PPC32 passes arguments to libc_start_main in some completely absurd way
			main_addr = self.state.mem_value(self.state.reg_expr(48) + 4, 4)
		else:
			# Get main pc from arguments
			main_addr = self.get_arg_value(0)

		self.add_exits(simuvex.s_exit.SimExit(expr=main_addr.expr, state=self.state))
		self.add_refs(simuvex.SimCodeRef(self.addr, self.stmt_from, main_addr, [], []))
