import simuvex
import symexec as se

######################################
# putchar
######################################

class putchar(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		write = simuvex.SimProcedures['syscalls']['write']

		string = self.get_arg_expr(0)
		self.inline_call(write, se.BitVecVal(1, self.state.arch.bits), string, 1)
		self.state['posix'].write(1, se.BitVecVal(0x0a, 8), 1)

		# TODO: return values
		self.exit_return()
