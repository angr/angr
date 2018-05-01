from . import ExplorationTechnique
import random


class StochasticSearch(ExplorationTechnique):

    def __init__(self, cfg):
        super(StochasticSearch, self).__init__()
        self.cfg = cfg

    def setup(self, simgr):
        self.affinity = StochasticSearch.random_affinity(self.cfg)
        self.first = simgr.active[0]

    def step(self, simgr, stash=None, **kwargs):
        if not simgr.stashes[stash] or random.random() < 0.0001:
            simgr.stashes[stash] = [self.first]
            self.affinity = StochasticSearch.random_affinity(self.cfg)

        if len(simgr.stashes[stash]) > 1:
            def weighted_pick(states):
                affinity = lambda s: self.affinity[s.addr]
                total_weight = sum((affinity(s) for s in states))
                selected = random.uniform(0, total_weight)
                for i, state in enumerate(states):
                    weight = self.affinity[state.addr]
                    if selected < weight:
                        break
                    else:
                        selected -= weight
                picked = states[i]
                return picked
            simgr.stashes[stash] = [weighted_pick(simgr.stashes[stash])]
        simgr = simgr.step(stash=stash, **kwargs)
        return simgr

    @staticmethod
    def random_affinity(cfg):
        return {addr: random.random() for addr in cfg.get_bbl_dict()}
