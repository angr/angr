
import logging

from ..calling_conventions import SYSCALL_CC
from ..errors import AngrUnsupportedSyscallError
from ..procedures import SIM_PROCEDURES as P
from .simos import SimOS

_l = logging.getLogger('angr.simos.userland')


class SimUserland(SimOS):
    """
    This is a base class for any SimOS that wants to support syscalls.

    It uses the CLE kernel object to provide addresses for syscalls. Syscalls will be emulated as a jump to one of these
    addresses, where a SimProcedure from the syscall library provided at construction time will be executed.
    """
    def __init__(self, project, syscall_library=None, **kwargs):
        super(SimUserland, self).__init__(project, **kwargs)
        self.syscall_library = syscall_library.copy()
        self.kernel_base = None

    def configure_project(self):
        super(SimUserland, self).configure_project()
        self.kernel_base = self.project.loader.kernel_object.mapped_base

    def syscall(self, state, allow_unsupported=True):
        """
        Given a state, return the procedure corresponding to the current syscall.
        This procedure will have .syscall_number, .display_name, and .addr set.

        :param state:               The state to get the syscall number from
        :param allow_unsupported:   Whether to return a "dummy" sycall instead of raising an unsupported exception
        """
        if state.os_name in SYSCALL_CC[state.arch.name]:
            cc = SYSCALL_CC[state.arch.name][state.os_name](state.arch)
        else:
            # Use the default syscall calling convention - it may bring problems
            _l.warning("No syscall calling convention available for %s/%s", state.arch.name, state.os_name)
            cc = SYSCALL_CC[state.arch.name]['default'](state.arch)

        sym_num = cc.syscall_num(state)
        possible = state.solver.eval_upto(sym_num, 2)

        if len(possible) == 0:
            raise AngrUnsupportedSyscallError("The program state is not satisfiable")
        elif len(possible) == 1:
            num = possible[0]
        elif allow_unsupported:
            num = self.syscall_library.maximum_syscall_number(self.arch.name) + 1 if self.syscall_library else 0
        else:
            raise AngrUnsupportedSyscallError("Got a symbolic syscall number")

        proc = self.syscall_from_number(num, allow_unsupported=allow_unsupported)
        proc.cc = cc
        return proc

    def is_syscall_addr(self, addr):
        """
        Return whether or not the given address corresponds to a syscall.
        """
        if self.kernel_base is None:
            return False
        addr -= self.kernel_base
        return 0 <= addr < 0x4000  # TODO: make this number come from somewhere

    def syscall_from_addr(self, addr, allow_unsupported=True):
        """
        Get a syscall SimProcedure from an address.

        :param addr: The address to convert to a syscall SimProcedure
        :param allow_unsupported: Whether to return a dummy procedure for an unsupported syscall instead of raising an
                                  exception.
        :return: The SimProcedure for the syscall, or None if the address is not a syscall address.
        """
        if not self.is_syscall_addr(addr):
            return None

        number = addr - self.kernel_base
        return self.syscall_from_number(number, allow_unsupported=allow_unsupported)

    def syscall_from_number(self, number, allow_unsupported=True):
        if not allow_unsupported and not self.syscall_library:
            raise AngrUnsupportedSyscallError("%s does not have a library of syscalls implemented" % self.name)

        addr = number + self.kernel_base

        if self.syscall_library is None:
            proc = P['stubs']['syscall']()
        elif not allow_unsupported and not self.syscall_library.has_implementation(number, self.arch):
            raise AngrUnsupportedSyscallError("No implementation for syscall %d" % number)
        else:
            proc = self.syscall_library.get(number, self.arch)

        proc.addr = addr
        return proc
