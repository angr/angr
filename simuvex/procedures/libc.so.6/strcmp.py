import simuvex

######################################
# strcmp
######################################

class strcmp(simuvex.SimProcedure):
	def __init__(self):
		# TODO: handle symbolic and static modes

		# src and dst
		arg_reg_offsets = self.get_arg_reg_offsets()
		# self.add_refs(simuvex.SimRegRead(-1, -1, arg_reg_offsets[0], self.get_arg_expr(0), 8))
		# self.add_refs(simuvex.SimRegRead(-1, -1, arg_reg_offsets[1], self.get_arg_expr(1), 8))
		self.add_refs(simuvex.SimRegWrite(-1, -1, 16, self.get_arg_value(0), 8, [arg_reg_offsets[0], arg_reg_offsets[1]], []))

		self.exit_return()
