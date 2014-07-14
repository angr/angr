import simuvex
from simuvex.s_type import SimTypePointer

######################################
# free
######################################
class free(simuvex.SimProcedure):
	def __init__(self):
                self.argument_types = {0: self.ty_ptr(SimTypeTop())}
		# TODO: if the return address cannot be concretized?
		self.exit_return()
