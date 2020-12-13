
import logging
from .common import condition_to_lambda
from . import ExplorationTechnique

l = logging.getLogger("angr.exploration_techniques.symbion")
# l.setLevel(logging.DEBUG)


class Symbion(ExplorationTechnique):
    """
    The Symbion exploration technique uses the SimEngineConcrete available to step a SimState.

    :param find: address or list of addresses that we want to reach, these will be translated into breakpoints
        inside the concrete process using the ConcreteTarget interface provided by the user
        inside the SimEngineConcrete.
    :param memory_concretize: list of tuples (address, symbolic variable) that are going to be written
        in the concrete process memory.
    :param register_concretize: list of tuples (reg_name, symbolic variable) that are going to be written
    :param timeout: how long we should wait the concrete target to reach the breakpoint

    """

    def __init__(self, find=None, memory_concretize=None, register_concretize=None, timeout=0, find_stash='found'):
        super(Symbion, self).__init__()

        # need to keep the raw list of addresses to
        self.breakpoints = find
        self.find = condition_to_lambda(find)
        self.memory_concretize = memory_concretize
        self.register_concretize = register_concretize
        self.find_stash = find_stash
        self.timeout = timeout

    def setup(self, simgr):
        # adding the 'found' stash during the setup
        simgr.stashes[self.find_stash] = []

    def step(self, simgr, stash='active', **kwargs):
        # safe guard
        if not len(simgr.stashes[stash]):
            l.warning("No stashes to step, aborting.")
            return None

        # check if the stash contains only one SimState and if not warn the user that only the
        # first state in the stash can be stepped in the SimEngineConcrete.
        # This because for now we support only one concrete execution, in future we can think about
        # a snapshot engine and give to each SimState an instance of a concrete process.
        if len(simgr.stashes[stash]) > 1:
            l.warning("You are trying to use the Symbion exploration technique on multiple state, "
                      "this is not supported now.")

        return simgr.step(stash=stash, **kwargs)

    def step_state(self, simgr, *args, **kwargs): #pylint:disable=arguments-differ
        state = args[0]
        ss = self.successors(state=state, simgr=simgr, engine=self.project.factory.concrete_engine,
                                          extra_stop_points=self.breakpoints,
                                          memory_concretize=self.memory_concretize,
                                          register_concretize=self.register_concretize,
                                          timeout=self.timeout)

        new_state = ss.successors

        if new_state[0].globals.get("symbion_timeout", None):
            return {'timeout': new_state}

        return {'found': new_state}

    def complete(self, simgr):
        # We are done if we have hit at least one breakpoint in
        # the concrete execution
        return len(simgr.stashes[self.find_stash]) >= 1
