import logging
l = logging.getLogger(name=__name__)

from .engine import SimEngine

#pylint: disable=arguments-differ

class SimEngineProcedure(SimEngine):
    """
    An engine for running SimProcedures
    """
    requires_project = False

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
