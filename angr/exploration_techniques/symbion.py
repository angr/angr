
import logging

from . import ExplorationTechnique

l = logging.getLogger("angr.exploration_techniques.symbion")
#l.setLevel(logging.DEBUG)


class Symbion(ExplorationTechnique):
    """
     The Symbion exploration technique uses the SimEngineConcrete available to step a SimState.
     :param find: address or list of addresses that we want to reach, these will be translated into breakpoints
                  inside the concrete process using the ConcreteTarget interface provided by the user
                  inside the SimEngineConcrete.
     :param concretize: list of tuples (address, symbolic variable) to concretize and write inside
                        the concrete process.
    """
    def __init__(self, find=[], concretize=[], find_stash='found'):
        super(Symbion, self).__init__()

        # need to keep the raw list of addresses to
        self.breakpoints = find
        self.find = self._condition_to_lambda(find)
        self.concretize = concretize
        self.find_stash = find_stash

    def setup(self, simgr):
        # adding the 'found' stash during the setup
        simgr.stashes[self.find_stash] = []

    def step(self, simgr, stash, **kwargs):
        # safe guard
        if not len(simgr.stashes[stash]):
            l.warning("No stashes to step, aborting.")
            return

        # check if the stash contains only one SimState and if not warn the user that only the
        # first state in the stash can be stepped in the SimEngineConcrete.
        # This because for now we support only one concrete execution, in future we can think about
        # a snapshot engine and give to each SimState an instance of a concrete process.
        if len(simgr.stashes[stash]) > 1:
            l.warning("You are trying to use the Symbion exploration technique on multiple state, "
                      "this is not supported now.")

        return simgr.step(stash=stash, **kwargs)

    def step_state(self, simgr, state, successor_func=None, **kwargs):
        ss = self.project.factory.successors(state, engines=['concrete'],
                                             extra_stop_points=self.breakpoints, concretize=self.concretize)

        return {'found': ss.successors}

    def complete(self, simgr):
        # We are done if we have hit at least one breakpoint in
        # the concrete execution
        return len(simgr.stashes[self.find_stash]) >= 1