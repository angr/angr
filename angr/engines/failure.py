from __future__ import annotations

import logging

from angr.errors import AngrExitError
from .successors import SuccessorsEngine
from .procedure import ProcedureMixin

l = logging.getLogger(name=__name__)


class SimEngineFailure(SuccessorsEngine, ProcedureMixin):
    def process_successors(self, successors, **kwargs):
        state = self.state
        jumpkind = state.history.parent.jumpkind if state.history and state.history.parent else None

        if jumpkind in ("Ijk_EmFail", "Ijk_MapFail") or (jumpkind is not None and jumpkind.startswith("Ijk_Sig")):
            raise AngrExitError(f"Cannot execute following jumpkind {jumpkind}")

        if jumpkind == "Ijk_Exit":
            from angr.procedures import SIM_PROCEDURES

            l.debug("Execution terminated at %#x", state.addr)
            terminator = SIM_PROCEDURES["stubs"]["PathTerminator"](project=self.project)
            return self.process_procedure(state, successors, terminator, **kwargs)

        return super().process_successors(successors, **kwargs)
