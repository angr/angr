import logging
import copy
from collections import defaultdict

from .plugin import SimStatePlugin


l = logging.getLogger('angr.state_plugins.loop_data')


class SimStateLoopData(SimStatePlugin):
    """
    This class keeps track of loop-related information for states.
    """

    def __init__(self, trip_counts=None, current_loop=None):
        """
        :param trip_counts : Dictionary that stores trip counts for each loop. Keys are address of loop headers.
        :param current_loop: List of currently running loops. Each element is a tuple (loop object, list of loop exits).
        """

        SimStatePlugin.__init__(self)

        self.trip_counts = defaultdict(list) if trip_counts is None else trip_counts
        self.current_loop = [] if current_loop is None else current_loop

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        l.warning("Merging is not implemented for loop data!")
        return False

    def widen(self, others): # pylint: disable=unused-argument
        l.warning("Widening is not implemented for loop data!")
        return False

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        return SimStateLoopData(trip_counts=copy.deepcopy(self.trip_counts),
                                current_loop=list(self.current_loop))


from angr.sim_state import SimState
SimState.register_default('loop_data', SimStateLoopData)
