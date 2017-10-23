import logging
l = logging.getLogger("angr.engines.syscall")

from .engine import SimEngine

class SimEngineSyscall(SimEngine): #pylint:disable=abstract-method
    def __init__(self, project):
        super(SimEngineSyscall, self).__init__()
        self.project = project

    def _check(self, state, **kwargs):
        return state.history.jumpkind.startswith('Ijk_Sys')

    def process(self, state, **kwargs):
        l.debug("Invoking system call handler")
        sys_procedure = self.project._simos.syscall(state)

        if sys_procedure is None:
            if sim_options.BYPASS_UNSUPPORTED_SYSCALL not in state.options:
                raise AngrUnsupportedSyscallError("Trying to perform a syscall on an emulated system which is not currently cofigured to support syscalls. To resolve this, make sure that your SimOS is a subclass of SimUserspace.")
            else:
                try:
                    cc = SYSCALL_CC[state.arch.name][state.os_name]
                except KeyError:
                    try:
                        l.warning("No syscall calling convention available for %s/%s", state.arch.name, state.os_name)
                        cc = SYSCALL_CC[state.arch.name]['default']
                    except KeyError:
                        cc = None # some default will get picked down the line...

                sys_procedure = SIM_PROCEDURES['stubs']['syscall'](cc=cc)

        addr = state.se.eval(state._ip)
        return self.project.factory.procedure_engine.process(state, sys_procedure, force_addr=addr)

    #
    # Pickling
    #

    def __setstate__(self, state):
        super(SimEngineSyscall, self).__setstate__(state)
        self.project = state['project']

    def __getstate__(self):
        s = super(SimEngineSyscall, self).__getstate__()
        s['project'] = self.project
        return s

from .. import sim_options
from ..errors import AngrUnsupportedSyscallError
from ..procedures import SIM_PROCEDURES
from ..calling_conventions import SYSCALL_CC
