import simuvex

######################################
# Redirect the control flow to some other places
######################################

class Redirect(simuvex.SimProcedure):
	#pylint:disable=arguments-differ

	def analyze(self, redirect_to=None):
		if redirect_to is None:
			raise Exception("Please specify where you wanna jump to.")

		self._custom_name = "Redirect to 0x%08x" % redirect_to
		# There is definitely no refs
		self.add_exits(simuvex.SimExit(addr=redirect_to, \
									   state=self.initial_state, \
									   jumpkind="Ijk_Boring"))
