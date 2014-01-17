import simuvex

import logging
l = logging.getLogger('simuvex.procedures.syscalls')

# TODO: per-OS and per-arch
syscall_map = { }
syscall_map['AMD64'] = { }
syscall_map['AMD64'][60] = 'exit'
syscall_map['AMD64'][0] = 'read'
syscall_map['AMD64'][1] = 'write'
syscall_map['AMD64'][2] = 'open'
syscall_map['AMD64'][3] = 'close'

class handler(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		syscall_num = self.get_syscall_value()
		maximum = self.state['posix'].maximum_symbolic_syscalls
		possible = syscall_num.any_n(maximum+1)

		if len(possible) > maximum:
			l.warning("Too many possible syscalls. Concretizing to 1.")
			possible = possible[:1]

		l.debug("Possible syscall values: %s", possible)

		for n in possible:
			callname = syscall_map[self.state.arch.name][n]
			l.debug("Routing to syscall %s", callname)

			sproc = simuvex.SimProcedures['syscalls'][callname]
			self.copy_run(sproc(self.state.copy_after(), self.state.reg_expr(self.state.arch.ip_offset)))

	def get_syscall_value(self):
		if self.state.arch.name == 'AMD64':
			return self.state.reg_value(16)

		raise Exception("get_syscall_value is not implemented for architecture %s", self.state.arch.name)
