from . import ExplorationTechnique
from difflib import SequenceMatcher
from collections import Counter


class UniqueSearch(ExplorationTechnique):

    def __init__(self, similarity_func=None, deferred_stash='deferred'):
        super(UniqueSearch, self).__init__()
        self.similarity_func = similarity_func or UniqueSearch.similarity
        self.deferred_stash = deferred_stash

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []
        self.uniqueness = dict()
        self.num_deadended = 0

    def step(self, simgr, stash=None, **kwargs):
        old_states = simgr.stashes[self.deferred_stash][:]
        new_states = simgr.stashes[stash]
        simgr.move(from_stash=stash, to_stash=self.deferred_stash)

        def update_average(state, new, z=1.0):
            # z is memory parameter, 0 = completely forget the past, 1 = completely track the past
            prev, n = self.uniqueness[state]
            new_average = float(prev * (n ** z) + new) / ((n ** z) + 1)
            self.uniqueness[state] = new_average, n + 1

        for state_a in new_states:
            self.uniqueness[state_a] = 0, 0
            for state_b in old_states:
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)
                update_average(state_b, similarity)
            for state_b in filter(lambda s: s is not state_a, new_states):
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)

        for state_a in simgr.stashes[self.deferred_stash]:
            for state_b in simgr.deadended[self.num_deadended:]:
                similarity = self.similarity_func(state_a, state_b)
                update_average(state_a, similarity)
        self.num_deadended = len(simgr.deadended)

        unique_state = min(self.uniqueness.items(), key=lambda e: e[1])[0]
        del self.uniqueness[unique_state]

        simgr.move(from_stash=self.deferred_stash, to_stash=stash, filter_func=lambda s: s is unique_state)

        simgr = simgr.step(stash=stash, **kwargs)
        return simgr

    @staticmethod
    def similarity(state_a, state_b):
        a = Counter(state_a.history.bbl_addrs)
        b = Counter(state_b.history.bbl_addrs)
        normal_distance = sum((a.get(addr, 0) - b.get(addr, 0)) ** 2
                              for addr in set(a.keys() + b.keys())) ** 0.5
        return 1.0 / (1 + normal_distance)

    @staticmethod
    def sequence_matcher_similarity(state_a, state_b):
        a = tuple(state_a.history.bbl_addrs)
        b = tuple(state_b.history.bbl_addrs)
        return SequenceMatcher(a=a, b=b).ratio()
