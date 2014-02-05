import simuvex
import symexec

######################################
# memset
######################################

class memset(simuvex.SimProcedure):
        def __init__(self):
                plugin = self.state.get_plugin('libc')
		s_sim = self.get_arg_value(0)
		c_sim = self.get_arg_value(1)
		n_sim = self.get_arg_value(2)

		# TODO improve this
		n = n_sim.max() if n_sim.is_symbolic() else n_sim.any()
		v = symexec.Extract(7, 0, c_sim.expr)
		c_v = v
		for off in range(0, n):
			c_v = symexec.Concat(c_v, v)

		self.state.store_mem(s_sim, c_v)
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, s_sim, c_v, n*8, [], [], [], []))
		self.exit_return(s_sim.expr)	
