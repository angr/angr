import logging
l = logging.getLogger("angr.engines.syscall")

from .engine import SimEngine
class SimEngineSyscall(SimEngine): #pylint:disable=abstract-method
    def __init__(self, project):
        super(SimEngineSyscall, self).__init__()

        self.project = project

    def _check(self, state, **kwargs):
        if not state.history.last_jumpkind.startswith('Ijk_Sys'):
            return False

        return True

    def process(self, state, **kwargs):
        addr = state.se.any_int(state._ip)

        l.debug("Invoking system call handler")

        # The ip_at_syscall register is misused to save the return address for this syscall
        ret_to = state.regs._ip_at_syscall

        sys_procedure = self.project._simos.handle_syscall(state)
        return self.project.factory.procedure_engine.process(
                state,
                sys_procedure,
                force_addr=addr,
                ret_to=ret_to)

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
