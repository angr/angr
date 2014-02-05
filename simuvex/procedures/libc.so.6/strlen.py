import simuvex
import symexec


######################################
# strlen
######################################

# TODO: move this kind of variable to a global level
# set bigger
max_str_size = 1024

class strlen(simuvex.SimProcedure):
        def __init__(self):
		s = self.get_arg_value(0)

		pos_eof = max_str_size
		for i in range(0, max_str_size):
			b = self.state.mem_value(s.expr + i, 1)
			# TODO: improve this approach
			if not b.is_symbolic() and b.any() == 0:
				pos_eof = i
				break

		# TODO: is ref necessary?
		self.exit_return(symexec.BitVecVal(pos_eof, self.state.arch.bits))
