import logging

from .engine import SimEngine
from .successors import SimSuccessors
from ..misc.ux import once

l = logging.getLogger(name=__name__)


# pylint: disable=abstract-method,unused-argument,arguments-differ
class SimEngineHook(SimEngine):

    def __init__(self, *args, **kwargs):
        super(SimEngineHook, self).__init__(*args, **kwargs)

        if once('sim_engine_hook'):
            print("\x1b[31;1mDeprecation warning: SimProcedures are now engines on their own."
                  "Consider using EngineSelector.insert_engine() to mark an address (or a memory range)"
                  "to be executed with a particular SimProcedure.\x1b[0m")

    def _check(self, state, procedure=None, **kwargs):
        # we have not yet entered the next step - we should check the "current" jumpkind
        if state.history.jumpkind == 'Ijk_NoHook':
            return False

        if state._ip.symbolic:
            # symbolic IP is not supported
            return False

        if procedure is None:
            if state.addr not in self.project._sim_procedures:
                if state.arch.name.startswith('ARM') and state.addr & 1 == 1 and state.addr - 1 in self.project._sim_procedures:
                    return True
                return False

        return True

    def process(self, state, procedure=None, force_addr=None, **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param procedure:   An instance of a SimProcedure to run, optional
        :param ret_to:      The address to return to when this procedure is finished
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        addr = state.addr if force_addr is None else force_addr

        if procedure is None:
            if addr not in self.project._sim_procedures:
                if state.arch.name.startswith('ARM') and addr & 1 == 1 and addr - 1 in self.project._sim_procedures:
                    procedure = self.project._sim_procedures[addr - 1]
                else:
                    return SimSuccessors.failure()
            else:
                procedure = self.project._sim_procedures[addr]

        l.debug("Running %s (originally at %#x)", repr(procedure), addr)
        return self.project.factory.procedure_engine.process(state, procedure, force_addr=force_addr, **kwargs)
