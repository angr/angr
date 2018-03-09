from . import ExplorationTechnique
from .. import sim_options

import logging
l = logging.getLogger("angr.exploration_techniques.symbion")

class Symbion(ExplorationTechnique):
    """
     The Symbion exploration technique uses only the SimEngineConcrete available in order
     to step a SimState.
     :param find: address or list of addresses that we want to reach, these will be translated into breakpoints
                  inside the concrete process using the ConcreteTarget interface provided by the user
                  that is living inside the SimEngineConcrete.
    """
    def __init__(self, find=None, find_stash='found'):
        super(Symbion, self).__init__()
        self.find = find
        self.find_stash = find_stash

    def setup(self, simgr):
        if not self.find_stash in simgr.stashes:
            simgr.stashes[self.find_stash] = []

    def filter(self, state):
        # check possible conditions on the state that we need to step inside the SimEngineConcrete
        return True

    def step(self, simgr, stash, **kwargs):
        # check if the stash contains only one SimState and if not warn the user that only the first state
        # in the stash can be stepped in the SimEngineConcrete.
        # This because for now we support only one concrete execution, in future we can think about a snapshot
        # engine and give to each SimState an instance of a concrete process.
        if len(simgr.stashes[stash]):
            l.warning(self, "You are trying to use the Symbion exploration technique on multiple state,"
                            "this is not supported now.")

        return simgr._one_step(stash=simgr.stashes[stash][0], **kwargs)

    def step_state(self, state, **kwargs):
        """
        This function will force the step of the state
        inside an instance of a SimConcreteEngine, passing the breakpoint
        addresses defined by the user ( aka 'find' ).
        :param state: the state to step inside the SimConcreteEngine
        :param kwargs:
        :return:
        """
        ss = self.project.factory.successors(state, engine=self.project.factory.concrete_engine,
                                             extra_stop_points=self.find)
        return ss

    def complete(self, simgr):
        return

