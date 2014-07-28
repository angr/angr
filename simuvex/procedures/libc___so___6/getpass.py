import simuvex

######################################
# getpass
######################################

class getpass(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		prompt = self.arg(0)

		# write out the prompt
		self.inline_call(simuvex.SimProcedures['libc.so.6']['puts'], prompt)

		# malloc a buffer
		buf = self.inline_call(simuvex.SimProcedures['libc.so.6']['malloc'], 1024).ret_expr

		# read into the buffer
		self.inline_call(simuvex.SimProcedures['libc.so.6']['read'], 0, buf, 1024)

		# return the buffer
		self.ret(buf)
