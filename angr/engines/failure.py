from .engine import SimEngine

import logging
l = logging.getLogger(name=__name__)

class SimEngineFailure(SimEngine): #pylint:disable=abstract-method
    def _check(self, state, *args, **kwargs):
        jumpkind = state.history.jumpkind

        if jumpkind in ('Ijk_EmFail', 'Ijk_MapFail') or (jumpkind is not None and jumpkind.startswith('Ijk_Sig')):
            return True
        if jumpkind == 'Ijk_Exit':
            return True
        return False

    def process(self, state, *args, **kwargs):

        from ..procedures import SIM_PROCEDURES

        if state.history.jumpkind in ("Ijk_EmFail", "Ijk_MapFail") or "Ijk_Sig" in state.history.jumpkind:
            raise AngrExitError("Cannot execute following jumpkind %s" % state.history.jumpkind)

        elif state.history.jumpkind == 'Ijk_Exit':
            l.debug('Execution terminated at %#x', state.addr)
            terminator = SIM_PROCEDURES['stubs']['PathTerminator'](project=self.project)
            return self.project.factory.procedure_engine.process(state, terminator, force_addr=state.addr)

        else:
            return SimSuccessors.failure()

from ..errors import AngrExitError
from .successors import SimSuccessors
