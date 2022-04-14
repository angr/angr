import logging
from typing import Dict, Tuple

from ..calling_conventions import SYSCALL_CC, SimCCSyscall
from ..errors import AngrUnsupportedSyscallError, SimSolverError
from ..procedures import SIM_PROCEDURES as P
from .simos import SimOS

_l = logging.getLogger(name=__name__)


class SimUserland(SimOS):
    """
    This is a base class for any SimOS that wants to support syscalls.

    It uses the CLE kernel object to provide addresses for syscalls. Syscalls will be emulated as a jump to one of these
    addresses, where a SimProcedure from the syscall library provided at construction time will be executed.
    """
    def __init__(self, project, syscall_library=None, syscall_addr_alignment=4, **kwargs):
        super(SimUserland, self).__init__(project, **kwargs)
        self.syscall_library = syscall_library.copy()
        self.syscall_addr_alignment = syscall_addr_alignment
        self.kernel_base = None
        self.unknown_syscall_number = None
        self.syscall_abis: Dict[str,Tuple[int,int,int]] = {}
        # syscall_abis is a dict of tuples {name: (base_number, min_number, max_number)}
        # min_number and max_number are just cached from SimSyscallLibrary.{min,max}imum_sysall_number
        # base_number is used to map the syscalls into the syscall address space - it's a "base address"
        # but a number. to convert from syscall number to address it's (number - min_num + base_num) * alignment + kernel_base

    def configure_project(self, abi_list=None): # pylint: disable=arguments-differ
        if abi_list is None:
            abi_list = list(self.syscall_library.syscall_number_mapping)
            assert len(abi_list) == 1, "More than one ABI is available for this target - you need to specify which ones are valid"
        self.kernel_base = self.project.loader.kernel_object.mapped_base

        base_no = 0
        for abi in abi_list:
            assert abi in self.syscall_library.syscall_number_mapping
            min_no = self.syscall_library.minimum_syscall_number(abi)
            max_no = self.syscall_library.maximum_syscall_number(abi)
            self.syscall_abis[abi] = (base_no, min_no, max_no)
            base_no += max_no - min_no + 1 # since max is the actual max and not the array length

        self.unknown_syscall_number = base_no

        # configure_project() involves lightweight symbolic execution, which may ends up using syscall ABIs. hence, we
        # need to fill in self.syscall_abis before calling configure_project().
        super().configure_project()

    def syscall_cc(self, state) -> SimCCSyscall:
        if state.os_name in SYSCALL_CC[state.arch.name]:
            cc = SYSCALL_CC[state.arch.name][state.os_name](state.arch)
        else:
            # Use the default syscall calling convention - it may bring problems
            _l.warning("No syscall calling convention available for %s/%s", state.arch.name, state.os_name)
            cc = SYSCALL_CC[state.arch.name]['default'](state.arch)
        return cc

    def syscall(self, state, allow_unsupported=True):
        """
        Given a state, return the procedure corresponding to the current syscall.
        This procedure will have .syscall_number, .display_name, and .addr set.

        :param state:               The state to get the syscall number from
        :param allow_unsupported:   Whether to return a "dummy" sycall instead of raising an unsupported exception
        """
        abi = self.syscall_abi(state)
        cc = self.syscall_cc(state)

        sym_num = cc.syscall_num(state)
        try:
            num = state.solver.eval_one(sym_num)
        except SimSolverError:
            if allow_unsupported:
                num = self.unknown_syscall_number
            else:
                if not state.solver.satisfiable():
                    raise AngrUnsupportedSyscallError("The program state is not satisfiable")
                else:
                    raise AngrUnsupportedSyscallError("Got a symbolic syscall number")

        proc = self.syscall_from_number(num, allow_unsupported=allow_unsupported, abi=abi)
        proc.cc = cc
        return proc

    def syscall_abi(self, state): # pylint: disable=unused-argument,no-self-use
        """
        Optionally, override this function to determine which abi is being used for the state's current syscall.
        """
        return None

    def is_syscall_addr(self, addr):
        """
        Return whether or not the given address corresponds to a syscall implementation.
        """
        if self.kernel_base is None or addr < self.kernel_base:
            return False

        addr -= self.kernel_base

        if addr % self.syscall_addr_alignment != 0:
            return False

        addr //= self.syscall_addr_alignment
        return addr <= self.unknown_syscall_number

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

        number = (addr - self.kernel_base) // self.syscall_addr_alignment
        for abi in self.syscall_abis:
            baseno, minno, maxno = self.syscall_abis[abi]
            if baseno <= number <= baseno + maxno - minno:
                number += minno
                number -= baseno
                break
        else:
            abi = None
        return self.syscall_from_number(number, allow_unsupported=allow_unsupported, abi=abi)

    def syscall_from_number(self, number, allow_unsupported=True, abi=None):
        """
        Get a syscall SimProcedure from its number.

        :param number:              The syscall number
        :param allow_unsupported:   Whether to return a "stub" syscall for unsupported numbers instead of throwing an error
        :param abi:                 The name of the abi to use. If None, will assume that the abis have disjoint
                                    numbering schemes and pick the right one.
        :return: The SimProcedure for the syscall
        """
        abilist = self.syscall_abis if abi is None else [abi]

        if self.syscall_library is None:
            if not allow_unsupported:
                raise AngrUnsupportedSyscallError("%s does not have a library of syscalls implemented" % self.name)
            proc = P['stubs']['syscall']()
        elif not allow_unsupported and not self.syscall_library.has_implementation(number, self.arch, abilist):
            raise AngrUnsupportedSyscallError("No implementation for syscall %d" % number)
        else:
            proc = self.syscall_library.get(number, self.arch, abilist)

        if proc.abi is not None:
            baseno, minno, _ = self.syscall_abis[proc.abi]
            mapno = number - minno + baseno
        else:
            mapno = self.unknown_syscall_number

        proc.addr = mapno * self.syscall_addr_alignment + self.kernel_base
        return proc
