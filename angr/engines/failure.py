from __future__ import annotations

import logging

import angr
from angr.errors import AngrExitError

from .procedure import ProcedureMixin
from .successors import SuccessorsEngine

log = logging.getLogger(name=__name__)


def is_failure_jumpkind(jumpkind: str | None) -> bool:
    """
    Check whether a jumpkind reports an emulation failure, a memory-mapping failure, or a signal.

    SimEngineFailure refuses to step a state that arrived on one of these, so anything choosing a
    successor to continue from has to skip them.
    """
    return jumpkind in ("Ijk_EmFail", "Ijk_MapFail") or (jumpkind is not None and jumpkind.startswith("Ijk_Sig"))


class SimEngineFailure(SuccessorsEngine, ProcedureMixin):
    def process_successors(self, successors, **kwargs):
        state = self.state
        jumpkind = state.history.parent.jumpkind if state.history and state.history.parent else None

        if is_failure_jumpkind(jumpkind):
            raise AngrExitError(f"Cannot execute following jumpkind {jumpkind}")

        if jumpkind == "Ijk_Exit":
            log.debug("Execution terminated at %#x", state.addr)
            terminator = angr.SIM_PROCEDURES["stubs"]["PathTerminator"](project=self.project)
            return self.process_procedure(state, successors, terminator, arguments=[], **kwargs)

        return super().process_successors(successors, **kwargs)
