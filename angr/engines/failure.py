from .engine import SimEngine

import logging
l = logging.getLogger("angr.engines.failure")

class SimEngineFailure(SimEngine): #pylint:disable=abstract-method
    def __init__(self, project):

        super(SimEngineFailure, self).__init__()

        self.project = project

    def _check(self, state, **kwargs):

        addr = state.se.any_int(state._ip)
        jumpkind = state.history.jumpkind

        if jumpkind in ('Ijk_EmFail', 'Ijk_MapFail') or jumpkind.startswith('Ijk_Sig'):
            return True
        if jumpkind == 'Ijk_NoDecode' and not self.project.is_hooked(addr):
            return True
        if jumpkind == 'Ijk_Exit':
            return True
        return False

    def process(self, state, **kwargs):

        from ..procedures import SIM_PROCEDURES

        addr = state.se.any_int(state._ip)

        if state.history.jumpkind in ("Ijk_EmFail", "Ijk_MapFail") or "Ijk_Sig" in state.history.jumpkind:
            raise AngrExitError("Cannot execute following jumpkind %s" % state.history.jumpkind)

        elif state.history.jumpkind == "Ijk_NoDecode" and not self.project.is_hooked(addr):
            raise AngrExitError("IR decoding error at %#x. You can hook this instruction with "
                                "a python replacement using project.hook"
                                "(%#x, your_function, length=length_of_instruction)." % (addr, addr))

        elif state.history.jumpkind == 'Ijk_Exit':
            l.debug('Execution terminated at %#x', addr)
            terminator = SIM_PROCEDURES['stubs']['PathTerminator'](project=self.project)
            peng = self.project.factory.procedure_engine
            return peng.process(state, terminator, force_addr=addr)

        else:
            return SimSuccessors.failure()

    #
    # Pickling
    #

    def __setstate__(self, state):
        super(SimEngineFailure, self).__setstate__(state)
        self.project = state['project']

    def __getstate__(self):
        s = super(SimEngineFailure, self).__getstate__()
        s['project'] = self.project
        return s

from ..errors import AngrExitError
from .successors import SimSuccessors
