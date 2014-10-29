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
        possible = self.state.se.any_n_int(syscall_num, maximum+1)

        if len(possible) > maximum:
            l.warning("Too many possible syscalls. Concretizing to 1.")
            possible = possible[:1]

        l.debug("Possible syscall values: %s", possible)
        self.state.add_constraints(self.state.se.Or(*[syscall_num == n for n in possible]))

        for n in possible:
            if n not in syscall_map[self.state.arch.name]:
                l.error("no syscall %d for arch %s", n, self.state.arch.name)
                if simuvex.o.BYPASS_UNSUPPORTED_SYSCALL in self.state.options:
                    self.ret(self.state.BV('syscall_%d' % n, self.state.arch.bits))
                    self.state.log.add_event('resilience', resilience_type='syscall', syscall=n, message='unsupported syscall')
                    return
                else:
                    raise simuvex.UnsupportedSyscallError("no syscall %d for arch %s", n, self.state.arch.name)

            callname = syscall_map[self.state.arch.name][n]
            l.debug("Routing to syscall %s", callname)

            sproc = simuvex.SimProcedures['syscalls'][callname]
            self.copy_run(sproc(self.state.copy(), ret_expr=self.state.reg_expr(self.state.arch.ip_offset)))

    def syscall_num(self):
        if self.state.arch.name == 'AMD64':
            return self.state.reg_expr(16)

        raise UnsupportedSyscallError("syscall_num is not implemented for architecture %s", self.state.arch.name)

from ...s_errors import UnsupportedSyscallError
