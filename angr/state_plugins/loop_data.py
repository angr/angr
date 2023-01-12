import logging
import copy
from collections import defaultdict

from .plugin import SimStatePlugin


l = logging.getLogger(name=__name__)


class SimStateLoopData(SimStatePlugin):
    """
    This class keeps track of loop-related information for states.
    Note that we have 2 counters for loop iterations (trip counts): the first
    recording the number of times one of the back edges (or continue edges) of
    a loop is taken, whereas the second recording the number of times the loop
    header (or loop entry) is executed. These 2 counters may differ since
    compilers usually optimize loops hence completely change the loop structure
    at the binary level.
    This is supposed to be used with `LoopSeer` exploration technique, which
    monitors loop execution. For the moment, the only thing we want to analyze
    is loop trip counts, but nothing prevents us from extending this plugin for
    other loop analyses.
    """

    def __init__(self, back_edge_trip_counts=None, header_trip_counts=None, current_loop=None):
        """
        :param back_edge_trip_counts: Dictionary that stores back edge based trip counts for each loop.
                                      Keys are address of loop headers.
        :param header_trip_counts:    Dictionary that stores header based trip counts for each loop.
                                      Keys are address of loop headers.
        :param current_loop:          List of currently running loops. Each element is a tuple
                                      (loop object, list of loop exits).
        """
        # This is why header based trip counter is not always accurate:
        #
        # 0x10812: movs r3, #0          -> this block dominates the loop
        # 0x10814: str  r3, [r7, #20]
        # 0x10816: b    0x10868
        #
        # 0x10818: movs r3, #0          -> the real loop body starts here
        # ...
        #
        # 0x10868: ldr  r3, [r7, #20]   -> the loop header is executed the first time without executing the loop body
        # 0x1086a: cmp  r3, #3
        # 0x1086c: ble  0x10818         -> the back edge
        #
        # This is why back edge based trip counter is not always accurate. The
        # compiler divides the logic of the loop body in 2 parts A and B. This loop
        # structure implies that the back edge is taken one time less than the number
        # of times the full loop body is executed.
        #
        # 0x10768: movs r3, #0          -> this block contains part A of the logic
        # ...                              for the first iteration and dominates the loop
        # 0x10816: b    0x10868
        #
        # 0x10818: movs r3, #0          -> part A of the logic for other iterations is put in this block
        # ...
        #
        # 0x10868: add  r2, r0, r1      -> part B of the logic for all iterations is put in the loop header
        # ...
        # 0x10898: ldr  r3, [r7, #20]
        # 0x1089a: cmp  r3, #3
        # 0x1089c: ble  0x10818         -> the back edge
        #
        # And yes, another example for the latter case is a do-while loop!

        SimStatePlugin.__init__(self)
        self.back_edge_trip_counts = defaultdict(list) if back_edge_trip_counts is None else back_edge_trip_counts
        self.header_trip_counts = defaultdict(list) if header_trip_counts is None else header_trip_counts
        self.current_loop = [] if current_loop is None else current_loop

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        l.warning("Merging is not implemented for loop data!")
        return False

    def widen(self, others):  # pylint: disable=unused-argument
        l.warning("Widening is not implemented for loop data!")
        return False

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimStateLoopData(
            back_edge_trip_counts=copy.deepcopy(self.back_edge_trip_counts),
            header_trip_counts=copy.deepcopy(self.header_trip_counts),
            current_loop=list(self.current_loop),
        )


from angr.sim_state import SimState

SimState.register_default("loop_data", SimStateLoopData)
