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
		syscall_num = self.syscall_num()
		maximum = self.state['posix'].maximum_symbolic_syscalls
		possible = self.state.se.any_n(syscall_num, maximum+1)

		if len(possible) > maximum:
			l.warning("Too many possible syscalls. Concretizing to 1.")
			possible = possible[:1]

		l.debug("Possible syscall values: %s", possible)

		for n in possible:
			callname = syscall_map[self.state.arch.name][n]
			l.debug("Routing to syscall %s", callname)

			sproc = simuvex.SimProcedures['syscalls'][callname]
			self.copy_run(sproc(self.state.copy(), self.state.reg_expr(self.state.arch.ip_offset)))

	def syscall_num(self):
		if self.state.arch.name == 'AMD64':
			return self.state.reg_expr(16)

		raise Exception("syscall_num is not implemented for architecture %s", self.state.arch.name)
