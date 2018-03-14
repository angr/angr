import logging

from .engine import SimEngine

l = logging.getLogger("angr.engines.hook")


# pylint: disable=abstract-method,unused-argument
class SimEngineHook(SimEngine):
    def __init__(self, project):
        super(SimEngineHook, self).__init__()
        self.project = project

    def _check(self, state, procedure=None, **kwargs):
        # we have not yet entered the next step - we should check the "current" jumpkind
        if state.history.jumpkind == 'Ijk_NoHook':
            return False

        if state._ip.symbolic:
            # symbolic IP is not supported
            return False

        if procedure is None:
            if state.addr not in self.project._sim_procedures:
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
                return
            else:
                procedure = self.project._sim_procedures[addr]

        l.debug("Running %s (originally at %#x)", repr(procedure), addr)
        return self.project.factory.procedure_engine.process(state, procedure, force_addr=force_addr, **kwargs)

    #
    # Pickling
    #

    def __setstate__(self, state):
        super(SimEngineHook, self).__setstate__(state)
        self.project = state['project']

    def __getstate__(self):
        s = super(SimEngineHook, self).__getstate__()
        s['project'] = self.project
        return s
