from __future__ import annotations
import logging

from .engine import SuccessorsMixin
from .procedure import ProcedureMixin
from archinfo.arch_soot import SootAddressDescriptor

l = logging.getLogger(name=__name__)


# pylint: disable=abstract-method,unused-argument,arguments-differ
class HooksMixin(SuccessorsMixin, ProcedureMixin):
    """
    A SimEngine mixin which adds a SimSuccessors handler which will look into the project's hooks and run the hook at
    the current address.

    Will respond to the following parameters provided to the step stack:

    - procedure:        A SimProcedure instance to force-run instead of consulting the current hooks
    - ret_to:           An address to force-return-to at the end of the procedure
    """

    def _lookup_hook(self, state, procedure):
        # TODO this is moderately controversial. If the jumpkind was NoHook and the user provided the procedure
        # argument, which takes precedence?
        # tentative guess: passed argument takes priority
        if procedure is not None:
            return procedure

        # we have at this point entered the next step - we should check the "previous" jumpkind
        if state.history and state.history.parent and state.history.parent.jumpkind == "Ijk_NoHook":
            return None

        if type(state._ip) is not int and state._ip.symbolic:
            # symbolic IP is not supported
            return None

        addr = state.addr
        procedure = self.project._sim_procedures.get(addr, None)
        if procedure is not None:
            return procedure

        if not state.arch.name.startswith("ARM") or addr & 1 != 1:
            return None

        procedure = self.project._sim_procedures.get(addr - 1, None)
        if procedure is not None:
            return procedure

        return None

    def process_successors(self, successors, procedure=None, **kwargs):
        state = self.state
        if procedure is None:
            procedure = self._lookup_hook(state, procedure)
        if procedure is None:
            return super().process_successors(successors, procedure=procedure, **kwargs)

        if isinstance(procedure.addr, SootAddressDescriptor):
            l.debug("Running %s (originally at %r)", repr(procedure), procedure.addr)
        else:
            l.debug(
                "Running %s (originally at %s)",
                repr(procedure),
                procedure.addr if procedure.addr is None else hex(procedure.addr),
            )

        return self.process_procedure(state, successors, procedure, **kwargs)
