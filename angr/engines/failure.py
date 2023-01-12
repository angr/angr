from .engine import SuccessorsMixin
from .procedure import ProcedureMixin

import logging

l = logging.getLogger(name=__name__)


class SimEngineFailure(SuccessorsMixin, ProcedureMixin):
    def process_successors(self, successors, **kwargs):
        state = self.state
        jumpkind = state.history.parent.jumpkind if state.history and state.history.parent else None

        if jumpkind in ("Ijk_EmFail", "Ijk_MapFail") or (jumpkind is not None and jumpkind.startswith("Ijk_Sig")):
            raise AngrExitError("Cannot execute following jumpkind %s" % jumpkind)

        if jumpkind == "Ijk_Exit":
            from ..procedures import SIM_PROCEDURES

            l.debug("Execution terminated at %#x", state.addr)
            terminator = SIM_PROCEDURES["stubs"]["PathTerminator"](project=self.project)
            return self.process_procedure(state, successors, terminator, **kwargs)

        return super().process_successors(successors, **kwargs)


from ..errors import AngrExitError
