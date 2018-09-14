import angr
import logging
l = logging.getLogger("angr.engines.syscall")

from .engine import SimEngine

#pylint:disable=abstract-method,arguments-differ
class SimEngineSyscall(SimEngine):
    def _check(self, state, **kwargs):
        return state.history.jumpkind.startswith('Ijk_Sys')

    def process(self, state, **kwargs):
        l.debug("Invoking system call handler")
        sys_procedure = self.project.simos.syscall(state)

        if sys_procedure is None:
            if angr.sim_options.BYPASS_UNSUPPORTED_SYSCALL not in state.options:
                raise AngrUnsupportedSyscallError("Trying to perform a syscall on an emulated system which is not currently cofigured to support syscalls. To resolve this, make sure that your SimOS is a subclass of SimUserspace, or set the BYPASS_UNSUPPORTED_SYSCALL state option.")
            else:
                try:
                    cc = angr.SYSCALL_CC[state.arch.name][state.os_name](state.arch)
                except KeyError:
                    try:
                        l.warning("No syscall calling convention available for %s/%s", state.arch.name, state.os_name)
                        cc = angr.SYSCALL_CC[state.arch.name]['default'](state.arch)
                    except KeyError:
                        cc = None # some default will get picked down the line...

                sys_procedure = angr.SIM_PROCEDURES['stubs']['syscall'](cc=cc)

        addr = state.solver.eval(state._ip)
        return self.project.factory.procedure_engine.process(state, sys_procedure, force_addr=addr)

from ..errors import AngrUnsupportedSyscallError
