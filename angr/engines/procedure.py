import logging
l = logging.getLogger(name=__name__)

from .engine import SimEngine
from ..misc.ux import once

#pylint: disable=arguments-differ

class SimEngineProcedure(SimEngine):
    """
    An engine for running SimProcedures
    """
    requires_project = False

    def __init__(self, *args, **kwargs):
        super(SimEngineProcedure, self).__init__(*args, **kwargs)

        if once('sim_engine_hook'):
            print("\x1b[31;1mDeprecation warning: SimProcedures are now engines on their own."
                  "You can run them directly using the instance process() method.\x1b[0m")

    def process(self, state, procedure=None, ret_to=None, **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param procedure:   An instance of a SimProcedure to run.
        :param ret_to:      The address to return to when this procedure is finished
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        return procedure.process(state, ret_to=ret_to, **kwargs)

    def _check(self, state, *args, **kwargs):
        return True
