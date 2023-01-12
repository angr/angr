import logging
from collections import defaultdict

from . import ExplorationTechnique


l = logging.getLogger(name=__name__)


class LocalLoopSeer(ExplorationTechnique):
    """
    LocalLoopSeer monitors exploration and maintains all loop-related data without relying on a control flow graph.
    """

    def __init__(self, bound=None, bound_reached=None, discard_stash="spinning"):
        """
        :param bound:                 Limit the number of iterations a loop may be executed.
        :param bound_reached:         If provided, should be a function that takes the LoopSeer and the succ_state.
                                      Will be called when loop execution reach the given bound.
                                      Default to moving states that exceed the loop limit to a discard stash.
        :param discard_stash:         Name of the stash containing states exceeding the loop limit.
        """

        super().__init__()
        self.bound = bound
        self.bound_reached = bound_reached
        self.discard_stash = discard_stash
        self.block_counters = defaultdict(int)
        self.cut_succs = []

    def setup(self, simgr):
        pass

    def filter(self, simgr, state, **kwargs):
        if state in self.cut_succs:
            self.cut_succs.remove(state)
            return self.discard_stash
        else:
            return simgr.filter(state, **kwargs)

    def successors(self, simgr, state, **kwargs):
        succs = simgr.successors(state, **kwargs)

        for succ_state in succs.successors:
            # Processing a currently running loop

            if succ_state._ip.symbolic:
                continue
            succ_addr = succ_state.addr

            # If we have set a bound for symbolic/concrete loops we want to handle it here
            if self.bound is not None:
                counts = succ_state.history.bbl_addrs.count(succ_addr)
                if counts > self.bound:
                    if self.bound_reached is not None:
                        # We want to pass self to modify the LocalLoopSeer state if needed
                        # Users can modify succ_state in the handler to implement their own logic
                        # or edit the state of LocalLoopSeer.
                        self.bound_reached(self, succ_state)
                    else:
                        # Remove the state from the successors object
                        # This state is going to be filtered by the self.filter function
                        self.cut_succs.append(succ_state)
        return succs
