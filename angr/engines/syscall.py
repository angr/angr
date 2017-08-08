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
        addr = state.se.any_int(state._ip)
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
