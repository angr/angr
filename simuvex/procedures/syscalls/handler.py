import simuvex
import simuvex.s_cc

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
syscall_map['AMD64'][4] = 'stat'
syscall_map['AMD64'][5] = 'fstat'
syscall_map['AMD64'][6] = 'lstat'
syscall_map['AMD64'][9] = 'mmap'
syscall_map['AMD64'][231] = 'exit' # really exit_group, but close enough

syscall_map['CGC'] = { }
syscall_map['CGC'][1] = '_terminate'
syscall_map['CGC'][2] = 'transmit'
syscall_map['CGC'][3] = 'receive'
syscall_map['CGC'][4] = 'fdwait'
syscall_map['CGC'][5] = 'allocate'
syscall_map['CGC'][6] = 'deallocate'
syscall_map['CGC'][7] = 'random'

class handler(simuvex.SimProcedure):
    def run(self):
        syscall_num = self.syscall_num()
        maximum = self.state['posix'].maximum_symbolic_syscalls
        possible = self.state.se.any_n_int(syscall_num, maximum+1)

        if len(possible) > maximum:
            l.warning("Too many possible syscalls. Concretizing to 1.")
            possible = possible[:1]

        l.debug("Possible syscall values: %s", possible)
        self.state.add_constraints(self.state.se.Or(*[syscall_num == n for n in possible]))

        for n in possible:
            if self.state.has_plugin('cgc'):
                map_name = 'CGC'
                syscall_lib = 'cgc'
            elif self.state.arch.name == 'X86':
                # FIXME: THIS IS A GIANT QUICK HACK FOR CGC SCORED EVENT 1!
                map_name = 'CGC'
                syscall_lib = 'cgc'
            else:
                map_name = self.state.arch.name
                syscall_lib = 'syscalls'

            if n not in syscall_map[map_name]:
                l.error("no syscall %d for arch %s", n, map_name)
                if simuvex.o.BYPASS_UNSUPPORTED_SYSCALL in self.state.options:
                    self.state.log.add_event('resilience', resilience_type='syscall', syscall=n, message='unsupported syscall')
                    return self.state.se.Unconstrained('syscall_%d' % n, self.state.arch.bits)
                else:
                    raise simuvex.UnsupportedSyscallError("no syscall %d for arch %s", n, map_name)

            callname = syscall_map[map_name][n]
            l.debug("Routing to syscall %s", callname)

            cc = simuvex.s_cc.SyscallCC[self.state.arch.name](self.state.arch)
            self._syscall = simuvex.SimProcedures[syscall_lib][callname](self.state, ret_to=self.state.regs.ip, convention=cc)
            self.successors.extend(self._syscall.successors)
            self.flat_successors.extend(self._syscall.successors)
            self.unsat_successors.extend(self._syscall.successors)

    def syscall_num(self):
        if self.state.arch.name == 'AMD64':
            return self.state.regs.rax
        if self.state.arch.name == 'X86':
            return self.state.regs.eax

        raise UnsupportedSyscallError("syscall_num is not implemented for architecture %s", self.state.arch.name)

from ...s_errors import UnsupportedSyscallError
