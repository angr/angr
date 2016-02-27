import types

import simuvex
import simuvex.s_cc

import logging
l = logging.getLogger('simuvex.procedures.syscalls')

class handler(simuvex.SimProcedure):
    # The NO_RET flag of handler is set to True, since normally it does not return - the real syscall would return.
    # However, if coming across an unsupported syscall, we will override this flag to False, since the real syscall is
    # not supported by angr, and handler must return
    NO_RET = True

    def run(self):
        #pylint:disable=attribute-defined-outside-init
        self._syscall=None
        self.callname = None
        syscall_num = self.syscall_num()

        if len(self.state.posix.queued_syscall_returns):
            #self.set_convention(simuvex.s_cc.SyscallCC[self.state.arch.name](self.state.arch))
            override = self.state.posix.queued_syscall_returns.pop(0)
            if override is None:
                pass
            elif isinstance(override, types.FunctionType):
                try:
                    override(self.state, run=self)
                except TypeError:
                    override(self.state)
                self.overriding_no_ret = False
                return
            else:
                self.overriding_no_ret = False
                return override

        if syscall_num.symbolic and simuvex.o.NO_SYMBOLIC_SYSCALL_RESOLUTION in self.state.options:
            self.overriding_no_ret = False
            l.debug("Not resolving symbolic syscall")
            return self.state.se.Unconstrained('unresolved_syscall', self.state.arch.bits)
        maximum = self.state.posix.maximum_symbolic_syscalls
        possible = self.state.se.any_n_int(syscall_num, maximum+1)

        if len(possible) == 0:
            self.overriding_no_ret = False
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

            if n not in syscall_table[map_name]:
                self.overriding_no_ret = False
                l.error("no syscall %d for arch %s", n, map_name)
                if simuvex.o.BYPASS_UNSUPPORTED_SYSCALL in self.state.options:
                    self.state.log.add_event('resilience', resilience_type='syscall', syscall=n, message='unsupported syscall')
                    return self.state.se.Unconstrained('syscall_%d' % n, self.state.arch.bits)
                else:
                    raise simuvex.UnsupportedSyscallError("no syscall %d for arch %s" % (n, map_name))

            self.callname = syscall_table[map_name][n]
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
from . import syscall_table
