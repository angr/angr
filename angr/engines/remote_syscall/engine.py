import logging
from typing import TYPE_CHECKING, List, Optional

l = logging.getLogger(name=__name__)

import angr
import claripy

from ...bureau.actions import BaseAction, SyscallReturnAction, WriteMemoryAction
from ...state_plugins.inspect import BP_BEFORE, BP_AFTER
from ..engine import SuccessorsMixin

if TYPE_CHECKING:
    from angr import SimState


#pylint:disable=abstract-method,arguments-differ
class SimEngineRemoteSyscall(SuccessorsMixin):
    """
    This mixin dispatches certain syscalls to a syscall agent that runs on another host (a local machine, a chroot jail,
    a Linux VM, a Windows VM, etc.).
    """

    def __init__(self, project, **kwargs):
        super().__init__(project, **kwargs)
        self.__description: str = ''
        self._syscall_proc: angr.SimProcedure = None

    __tls = ('__description', '_syscall_proc')

    def process_successors(self, successors, **kwargs):
        state: 'angr.SimState' = self.state
        if (not state.history or
                not state.history.parent or
                not state.history.parent.jumpkind or
                not state.history.parent.jumpkind.startswith('Ijk_Sys')):
            return super().process_successors(successors, **kwargs)

        syscall_proc = self.project.simos.syscall(state)
        syscall_num = syscall_proc.syscall_number
        syscall_name = syscall_proc.name
        syscall_args = [syscall_proc.arg(i) for i in range(len(syscall_proc.cc.func_ty.args))]

        self.__description = 'Syscall dispatch: ' + syscall_name
        self._syscall_proc = syscall_proc

        # inspect support
        self.state._inspect('syscall', BP_BEFORE, syscall_name=syscall_name)

        self.policy(syscall_num, syscall_name, syscall_args, **kwargs)

        # inspect - post execution
        self.state._inspect('syscall', BP_AFTER, syscall_name=syscall_name)

        # create the successor
        successors.sort = 'SimProcedure'

        # fill in artifacts
        successors.artifacts['is_syscall'] = True
        successors.artifacts['name'] = syscall_name
        successors.artifacts['no_ret'] = False  # TODO
        successors.artifacts['adds_exits'] = True  # TODO

        # Update state.scratch
        self.state.scratch.sim_procedure = None
        self.state.history.recent_block_count = 1

        # add the successor
        self.successors.add_successor(self.state, syscall_proc.cc.return_addr.get_value(self.state), claripy.true, jumpkind='Ijk_Ret')

        self.successors.description = self.__description
        self.successors.processed = True

    def policy(self, syscall_num, syscall_name, syscall_args, **kwargs):
        if syscall_name in basic_blacklist:
            self.apply_symbolic(self.dispatch_symbolic(syscall_args))
            return

        concrete_result = self.dispatch_concrete(syscall_args, syscall_num=syscall_num)
        if isinstance(self._syscall_proc, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']):
            self.apply_concrete(concrete_result)
            return

        symbolic_result = self.dispatch_symbolic(syscall_args)
        concrete_return = next(iter(r for r in concrete_result if isinstance(r, SyscallReturnAction)))
        if not (concrete_return.retval == self._syscall_proc.cc.ret_val.get_value(symbolic_result)).is_true():
            l.warning("Emulation warning: concrete and symbolic executions gave different return values")

        self.apply_symbolic(symbolic_result)

    def dispatch_concrete(self, args, syscall_num: Optional[int]=None, **kwargs) -> List[BaseAction]:
        l.debug("Invoking remote system call handler")
        if syscall_num is None:
            syscall_num = self._syscall_proc.syscall_number
        if isinstance(syscall_num, claripy.Base):
            if syscall_num.op == 'BVV':
                syscall_num = syscall_num.args[0]
            else:
                raise AngrSyscallError("Trying to push a symbolic syscall to the agent")
        for i in range(len(args)):
            if isinstance(args[i], claripy.Base):
                if args[i].op == 'BVV':
                    args[i] = args[i].args[0]
                else:
                    raise AngrSyscallError("Trying to push a symbolic syscall to the agent")

        self.__description += ' concrete()'
        return self.project.bureau.invoke_syscall(self.state, syscall_num, args, self._syscall_proc.cc)

    def dispatch_symbolic(self, args, proc=None, **kwargs):
        self.__description += ' symbolic()'
        state = self.state.copy()
        if proc is None:
            proc = self._syscall_proc

        # if we ever want syscalls to be able to use self.jump or add multiple successors, this will have to be reworked
        proc.execute(state, arguments=args)
        return state

    def apply_concrete(self, agent_results: List[BaseAction]):

        for action in agent_results:
            if isinstance(action, SyscallReturnAction):
                self._syscall_proc.cc.set_return_val(self.state, action.retval)
            elif isinstance(action, WriteMemoryAction):
                self.state.memory.store(action.addr, action.data, endness='Iend_BE')
            else:
                raise TypeError("Unsupported action type %s." % type(action))

    def apply_symbolic(self, result_state):
        self.state = result_state

basic_blacklist = [
    'mmap', 'munmap', 'mprotect', 'brk', 'sbrk',
    'exit', 'exit_group', 'set_thread_area'
]
from ...errors import AngrSyscallError, AngrUnsupportedSyscallError
