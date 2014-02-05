import simuvex
import symexec


# TODO: bigger
# TODO: global scope
max_str_size = 1024

def get_len(str_base, state):
	for i in range(0, max_str_size):
		b = state.mem_value(str_base.expr + i, 1)
		if not b.is_symbolic() and b.any() == 0:
			return i
	return max_str_size

class strcpy(simuvex.SimProcedure):
	def __init__(self):
		#TODO prevent overlapping!
		dest = self.get_arg_value(0)
		src = self.get_arg_value(1)
		
		length = get_len(src, self.state)		
                data = self.state.mem_expr(src.expr, length)
		self.state.store_mem(dest.expr, data)
		self.state.store_mem(dest.expr + length, symexec.BitVecVal(0, self.state.arch.bits))
	
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, src,
						data, length, (), ()))
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dest, 
						data, length, [], [], [], []))

		self.exit_return(dest.expr)

