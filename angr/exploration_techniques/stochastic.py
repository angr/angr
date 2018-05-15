import random

from . import ExplorationTechnique

class StochasticSearch(ExplorationTechnique):
    """
    Stochastic Search.

    Will only keep one path active at a time, any others will be discarded.
    Before each pass through, weights are randomly assigned to each basic block.
    These weights form a probability distribution for determining which state remains after splits.
    When we run out of active paths to step, we start again from the start state.
    """

    def __init__(self, start_state, cfg):
        """
        :param start_state: The initial state from which exploration stems.
        :param cfg:         The control flow graph of the explored program.
        """

        super(StochasticSearch, self).__init__()
        self.start_state = start_state
        self.cfg = cfg
        self.affinity = StochasticSearch.random_affinity(self.cfg)

    def step(self, simgr, stash=None, **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if not simgr.stashes[stash] or random.random() < 0.0001:
            simgr.stashes[stash] = [self.start_state]
            self.affinity = StochasticSearch.random_affinity(self.cfg)

        if len(simgr.stashes[stash]) > 1:
            def weighted_pick(states):
                """
                param states: Diverging states.
                """
                assert len(states) >= 2
                affinity = lambda s: self.affinity[s.addr]
                total_weight = sum((affinity(s) for s in states))
                selected = random.uniform(0, total_weight)
                i = 0
                for i, state in enumerate(states):
                    weight = self.affinity[state.addr]
                    if selected < weight:
                        break
                    else:
                        selected -= weight
                picked = states[i]
                return picked

            simgr.stashes[stash] = [weighted_pick(simgr.stashes[stash])]

        return simgr

    @staticmethod
    def random_affinity(cfg):
        """
        param cfg: The control flow graph to assign weights.
        """
        return {addr: random.random() for addr in cfg.get_bbl_dict()}
