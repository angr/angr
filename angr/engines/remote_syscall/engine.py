import logging
from typing import TYPE_CHECKING, List, Optional

l = logging.getLogger(name=__name__)

import angr
import claripy

from ...bureau.actions import BaseAction, SyscallReturnAction, WriteMemoryAction
from ...state_plugins.inspect import BP_BEFORE, BP_AFTER
from ..engine import SuccessorsMixin
from ...storage import file as simfile

if TYPE_CHECKING:
    from angr import SimState


#pylint:disable=abstract-method,arguments-differ
class SimEngineRemoteSyscall(SuccessorsMixin):
    """
    This mixin dispatches certain syscalls to a syscall agent that runs on another host (a local machine, a chroot jail,
    a Linux VM, a Windows VM, etc.).
    """

    def __init__(self, project, tainted_fds=None, **kwargs):
        super().__init__(project, **kwargs)
        self.__description: str = ''
        self._syscall_proc: angr.SimProcedure = None
        self.tainted_fds = {} if tainted_fds is None else tainted_fds

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
        syscall_name = syscall_proc.display_name
        syscall_args = [syscall_proc.cc.arg(self.state, i) for i in range(len(syscall_proc.cc.func_ty.args))]

        self.__description = 'Syscall dispatch: ' + syscall_name
        self._syscall_proc = syscall_proc

        # inspect support
        self.state._inspect('syscall', BP_BEFORE, syscall_name=syscall_name)

        self.state.scratch.jumpkind = 'Ijk_Ret'
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
        self.successors.add_successor(self.state, syscall_proc.cc.return_addr.get_value(self.state), claripy.true, jumpkind=self.state.scratch.jumpkind)

        self.successors.description = self.__description
        self.successors.processed = True

    def policy(self, syscall_num, syscall_name, syscall_args, **kwargs):
        print('HANDLING', syscall_name)
        if syscall_name in basic_blacklist:
            self.apply_symbolic(self.dispatch_symbolic(syscall_args))
            return

        fd_kind = None
        conc_args = list(syscall_args)

        # translate input args for file descriptors
        for i, (arg, ty) in enumerate(zip(syscall_args, self._syscall_proc.cc.func_ty.args)):
            if isinstance(ty, angr.sim_type.SimTypeFd):
                arg_conc = self.state.solver.eval_one(arg)
                if arg_conc not in self.state.posix.fd:
                    conc_args[i] = 0xffffffff
                else:
                    simfd = self.state.posix.fd[arg_conc]
                    if hasattr(simfd, 'remote_fd'):
                        conc_args[i] = simfd.remote_fd
                        kind = (True, type(simfd) is not simfile.RemoteFd)
                    else:
                        kind = (False, False)
                    if fd_kind is None:
                        fd_kind = kind
                    elif kind != fd_kind:
                        raise Exception("Syscall mixes remote and local file descriptors. this is not insurmountable but requires special logic")

        # if this syscall only deals with local file descriptors or memory management, just dispatch it symbolically
        if fd_kind == (False, False) or syscall_name in basic_blacklist:
            self.apply_symbolic(self.dispatch_symbolic(syscall_args))
            return

        fd_in_translated = fd_kind is not None and fd_kind[0]
        fd_in_taint = fd_kind is not None and fd_kind[1]

        concrete_result = self.dispatch_concrete(conc_args, syscall_num=syscall_num)
        concrete_return = next(iter(r for r in concrete_result if isinstance(r, SyscallReturnAction)))

        # assume that all syscalls that return file descriptors have just acquired them
        fd_returned = isinstance(self._syscall_proc.cc.func_ty.returnty, angr.sim_type.SimTypeFd) and 0 <= concrete_return.retval < 2**31
        fd_out_taint = fd_returned and (fd_in_taint or self.fd_taint_policy(syscall_name, syscall_args))

        # if this syscall returned a file descriptor that we don't want to taint, insert it, commit, and done
        # additional caveat: if we want to taint it but we can't (no proc impl) insert it
        if fd_returned and (not fd_out_taint or self._syscall_proc.is_stub):
            new_fd = self.state.posix._pick_fd()
            self.state.posix.fd[new_fd] = simfile.RemoteFd(concrete_return.retval)
            concrete_return.retval = new_fd
            self.apply_concrete(concrete_result)
            return

        if self._syscall_proc.is_stub or fd_in_translated:
            self.apply_concrete(concrete_result)
            return

        symbolic_result = self.dispatch_symbolic(syscall_args)
        if not (concrete_return.retval == self._syscall_proc.cc.return_val.get_value(symbolic_result)).is_true():
            l.warning("Emulation warning: concrete and symbolic executions gave different return values")

        if fd_returned:
            simfd = self.state.posix.get_fd(self._syscall_proc.cc.get_return_val(symbolic_result))
            if simfd is None:
                l.error("Syscall agent returned a file descriptor but symbolic implementation did not")
            else:
                simfd.remote_fd = concrete_return.retval

        self.apply_symbolic(symbolic_result)

    def fd_taint_policy(self, syscall_name, syscall_args):
        return False

    def dispatch_concrete(self, args, syscall_num: Optional[int]=None, **kwargs) -> List[BaseAction]:
        l.debug("Invoking remote system call handler")
        if syscall_num is None:
            syscall_num = self._syscall_proc.syscall_number
        if isinstance(syscall_num, claripy.ast.Base):
            if syscall_num.op == 'BVV':
                syscall_num = syscall_num.args[0]
            else:
                raise AngrSyscallError("Trying to push a symbolic syscall to the agent")
        for i in range(len(args)):
            if isinstance(args[i], claripy.ast.Base):
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

        successors = angr.engines.SimSuccessors(state.addr, state)
        inst = proc.execute(state, arguments=args, successors=successors, ret_to=proc.cc.return_addr.get_value(state))
        if len(successors.flat_successors) != 1:
            raise Exception("SimProcedure returned more than one successor")
        result = successors.flat_successors[0]
        result.scratch.jumpkind = result.history.jumpkind
        if inst.ret_expr is not None:
            proc.cc.set_return_val(result, inst.ret_expr)
        return result

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
from ...errors import AngrSyscallError
