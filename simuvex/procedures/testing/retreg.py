import simuvex

class retreg(simuvex.SimProcedure):
	def run(self, reg=None):
		r = self.state.reg_expr(reg)
		print self.state.options
		return r
