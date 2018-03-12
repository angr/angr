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
     :param concretize: list of symbolic variables to concretize and write inside
                        the concrete process.
    """
    def __init__(self, find=None, concretize=None, find_stash='found'):
        super(Symbion, self).__init__()
        self.find = find
        self.concretize = concretize
        self.find_stash = find_stash

        #addresses = map(hex,find)
        #print("Initialized Symbion with args: find = " + addresses + " concretize = " + str(concretize))

    def setup(self, simgr):
        # TODO is this find stash filled correctly?
        if not self.find_stash in simgr.stashes:
            simgr.stashes[self.find_stash] = []

    '''
    def filter(self, state):
        # check possible conditions on the state that we need to step inside the SimEngineConcrete
        return True
    '''

    def step(self, simgr, stash, **kwargs):

        if not len(simgr.stashes[stash]):
            l.warning(self, "No stashes to step, aborting.")
            return

        # check if the stash contains only one SimState and if not warn the user that only the first state
        # in the stash can be stepped in the SimEngineConcrete.
        # This because for now we support only one concrete execution, in future we can think about a snapshot
        # engine and give to each SimState an instance of a concrete process.
        if len(simgr.stashes[stash]) > 1:
            l.warning(self, "You are trying to use the Symbion exploration technique on multiple state,"
                            "this is not supported now.")

        # TODO is it ok to extract the first state in the stash in this way?
        return simgr._one_step(stash=stash, **kwargs)

    def step_state(self, state, **kwargs):
        """
        This function will force the step of the state
        inside an instance of a SimConcreteEngine, passing the breakpoint
        addresses defined by the user ( aka 'find' ).
        :param state: the state to step inside the SimConcreteEngine
        :param kwargs:
        :return:
        """
        ss = self.project.factory.successors(state, engines=[self.project.factory.concrete_engine],
                                             extra_stop_points=self.find, concretize=self.concretize)
        return ss

    def complete(self, simgr):
        # TODO anything here?
        return

