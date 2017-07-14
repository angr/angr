# pylint: disable=abstract-method,unused-argument

import logging
l = logging.getLogger("angr.engines.hook")

from .procedure import SimEngineProcedure
class SimEngineHook(SimEngineProcedure):
    def __init__(self, project):
        super(SimEngineHook, self).__init__()

        self.project = project

    def check(self, state,
              procedure=None,
              **kwargs):
        """
        Check if SimEngineHook can handle the current state or not.

        :param SimState state: The state to work with.
        :param SimProcedure procedure: An instance of a SimProcedure to run. Optional.
        :param kwargs:                 Other arguments.
        :return:                       True or False.
        :rtype:                        bool
        """

        return super(SimEngineHook, self).check(state, procedure, **kwargs)

    def process(self, state,
            procedure=None,
            ret_to=None,
            inline=None,
            force_addr=None, **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param procedure:   An instance of a SimProcedure to run, optional
        :param ret_to:      The address to return to when this procedure is finished
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        return super(SimEngineHook, self).process(state, procedure,
                ret_to=ret_to,
                inline=inline,
                force_addr=force_addr)

    def _check(self, state, procedure=None, **kwargs):
        # we have not yet entered the next step - we should check the "current" jumpkind
        if state.history.jumpkind == 'Ijk_NoHook':
            return False

        if state._ip.symbolic:
            # symbolic IP is not supported
            return False

        addr = state.se.exactly_int(state._ip)

        if procedure is None:
            if addr not in self.project._sim_procedures:
                return False

        return super(SimEngineHook, self)._check(state, procedure, **kwargs)

    def _process(self, state, successors, procedure=None, **kwargs):
        addr = successors.addr
        if state.history.parent.jumpkind == 'Ijk_NoHook':
            return

        if procedure is None:
            if addr not in self.project._sim_procedures:
                return
            else:
                procedure = self.project._sim_procedures[addr]

        l.debug("Running %s (originally at %#x)", repr(procedure), addr)
        return super(SimEngineHook, self)._process(state, successors, procedure, **kwargs)

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
