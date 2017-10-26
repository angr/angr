import logging

from collections import defaultdict

from .plugin import SimStatePlugin

l = logging.getLogger('angr.state_plugins.loop_data')


class SimStateLoopData(SimStatePlugin):
    """
    This class keeps track of loop-related information for states.
    """

    def __init__(self, trip_counts=None):
        """
        :param trip_counts: Dictionary that stores trip counts for each loop.
        """

        SimStatePlugin.__init__(self)

        if trip_counts is None:
            trip_counts = defaultdict(list)
        self.trip_counts = trip_counts

    def merge(self, others, merge_conditions, common_ancestor=None):
        l.warning("Merging is not implemented for loop data!")
        return False

    def widen(self, others):
        l.warning("Widening is not implemented for loop data!")
        return False

    def copy(self):
        return SimStateLoopData(trip_counts=self.trip_counts)

SimStateLoopData.register_default("loop_data", SimStateLoopData)
