import simuvex
import simuvex.s_cc

import logging
l = logging.getLogger('simuvex.procedures.syscalls')

# TODO: per-OS and per-arch
syscall_map = { }

syscall_map['AMD64'] = { }
syscall_map['AMD64'][0] = 'read'
syscall_map['AMD64'][1] = 'write'
syscall_map['AMD64'][2] = 'open'
syscall_map['AMD64'][3] = 'close'
syscall_map['AMD64'][4] = 'stat'
syscall_map['AMD64'][5] = 'fstat'
syscall_map['AMD64'][6] = 'stat'
syscall_map['AMD64'][9] = 'mmap'
syscall_map['AMD64'][60] = 'exit'
syscall_map['AMD64'][231] = 'exit' # really exit_group, but close enough

syscall_map['X86'] = { }
syscall_map['X86'][1] = 'exit'
syscall_map['X86'][3] = 'read'
syscall_map['X86'][4] = 'write'
syscall_map['X86'][5] = 'open'
syscall_map['X86'][6] = 'close'
syscall_map['X86'][252] = 'exit'    # exit_group

syscall_map['PPC32'] = {}
syscall_map['PPC64'] = {}
syscall_map['MIPS32'] = {}
syscall_map['MIPS64'] = {}
syscall_map['ARM'] = {}
syscall_map['ARMEL'] = syscall_map['ARM']
syscall_map['ARMHF'] = syscall_map['ARM']
syscall_map['AARCH64'] = {}

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
        #pylint:disable=attribute-defined-outside-init
        self._syscall=None
        self.callname = None
        syscall_num = self.syscall_num()
        if syscall_num.symbolic and simuvex.o.NO_SYMBOLIC_SYSCALL_RESOLUTION in self.state.options:
            l.debug("Not resolving symbolic syscall")
            return self.state.se.Unconstrained('unresolved_syscall', self.state.arch.bits)
        maximum = self.state.posix.maximum_symbolic_syscalls
        possible = self.state.se.any_n_int(syscall_num, maximum+1)

        if len(possible) == 0:
            raise SimUnsatError("unsatisifiable state attempting to do a syscall")

        if len(possible) > maximum:
            l.warning("Too many possible syscalls. Concretizing to 1.")
            possible = possible[:1]

        l.debug("Possible syscall values: %s", possible)
        self.state.add_constraints(self.state.se.Or(*[syscall_num == n for n in possible]))

        for n in possible:
            if self.state.has_plugin('cgc'):
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
                    raise simuvex.UnsupportedSyscallError("no syscall %d for arch %s" % (n, map_name))

            self.callname = syscall_map[map_name][n]
            l.debug("Routing to syscall %s", self.callname)

            cc = simuvex.s_cc.SyscallCC[self.state.arch.name](self.state.arch)
            self._syscall = simuvex.SimProcedures[syscall_lib][self.callname](self.state, ret_to=self.state.regs.ip, convention=cc)
            self.successors.extend(self._syscall.successors)
            self.flat_successors.extend(self._syscall.flat_successors)
            self.unsat_successors.extend(self._syscall.unsat_successors)

    def __repr__(self):
        return '<Syscall (%s)>' % ('Unsupported' if self.callname is None else self.callname)

    @property
    def syscall(self):
        return self._syscall

    def syscall_num(self):
        if self.state.arch.name == 'AMD64':
            return self.state.regs.rax
        if self.state.arch.name == 'X86':
            return self.state.regs.eax
        if self.state.arch.name in ('MIPS32', 'MIPS64'):
            return self.state.regs.v0
        if self.state.arch.name in ('ARM', 'ARMEL', 'ARMHF'):
            return self.state.regs.r7
        if self.state.arch.name == 'AARCH64':
            return self.state.regs.x8
        if self.state.arch.name in ('PPC32', 'PPC64'):
            return self.state.regs.r0

        raise UnsupportedSyscallError("syscall_num is not implemented for architecture %s" % self.state.arch.name)

from ...s_errors import UnsupportedSyscallError
from ...s_errors import SimUnsatError
