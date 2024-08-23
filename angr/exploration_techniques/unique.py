from __future__ import annotations
from difflib import SequenceMatcher
from collections import Counter

from . import ExplorationTechnique


class UniqueSearch(ExplorationTechnique):
    """
    Unique Search.

    Will only keep one path active at a time, any others will be deferred.
    The state that is explored depends on how unique it is relative to the other deferred states.
    A path's uniqueness is determined by its average similarity between the other (deferred) paths.
    Similarity is calculated based on the supplied `similarity_func`, which by default is:
    The (L2) distance between the counts of the state addresses in the history of the path.
    """

    def __init__(self, similarity_func=None, deferred_stash="deferred"):
        """
        :param similarity_func: How to calculate similarity between two states.
        :param deferred_stash:  Where to store the deferred states.
        """
        super().__init__()
        self.similarity_func = similarity_func or UniqueSearch.similarity
        self.deferred_stash = deferred_stash
        self.uniqueness = {}
        self.num_deadended = 0

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        old_states = simgr.stashes[self.deferred_stash][:]
        new_states = simgr.stashes[stash][:]
        simgr.move(from_stash=stash, to_stash=self.deferred_stash)

        def update_average(state, new, mem=1.0):
            """
            param state: The state to update the average for.
            param new:   The new value to be accumulated into the average.
            param mem:   Memory parameter to determine how to weight the past average.
            """
            prev, size = self.uniqueness[state]
            new_average = float(prev * (size**mem) + new) / ((size**mem) + 1)
            self.uniqueness[state] = new_average, size + 1

        for state_a in new_states:
            self.uniqueness[state_a] = 0, 0
            for state_b in old_states:
                # Update similarity averages between new and old states
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)
                update_average(state_b, similarity)
            for state_b in (s for s in new_states if s is not state_a):
                # Update similarity averages between new states
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)

        for state_a in simgr.stashes[self.deferred_stash]:
            for state_b in simgr.deadended[self.num_deadended :]:
                # Update similarity averages between all states and newly deadended states
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)
        self.num_deadended = len(simgr.deadended)

        if self.uniqueness:
            unique_state = min(self.uniqueness.items(), key=lambda e: e[1])[0]
            del self.uniqueness[unique_state]

            simgr.move(from_stash=self.deferred_stash, to_stash=stash, filter_func=lambda s: s is unique_state)

        return simgr

    @staticmethod
    def similarity(state_a, state_b):
        """
        The (L2) distance between the counts of the state addresses in the history of the path.
        :param state_a: The first state to compare
        :param state_b: The second state to compare
        """
        count_a = Counter(state_a.history.bbl_addrs)
        count_b = Counter(state_b.history.bbl_addrs)
        normal_distance = (
            sum(
                (count_a.get(addr, 0) - count_b.get(addr, 0)) ** 2
                for addr in set(list(count_a.keys()) + list(count_b.keys()))
            )
            ** 0.5
        )
        return 1.0 / (1 + normal_distance)

    @staticmethod
    def sequence_matcher_similarity(state_a, state_b):
        """
        The `difflib.SequenceMatcher` ratio between the state addresses in the history of the path.
        :param state_a: The first state to compare
        :param state_b: The second state to compare
        """
        addrs_a = tuple(state_a.history.bbl_addrs)
        addrs_b = tuple(state_b.history.bbl_addrs)
        return SequenceMatcher(a=addrs_a, b=addrs_b).ratio()
