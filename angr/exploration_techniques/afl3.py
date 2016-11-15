from collections import defaultdict
from .afl_base import AFLBase

class AFL3(AFLBase):
    """
    AFL-inspired exploration technique.

    This will keep advancing paths that so long as they keep producing new unseen control flow transitions. Once it runs
    out it will restart with all paths and again prune them while they do not produce new transitions until no paths are
    left over. Then it returns.
    """
    def __init__(self):
        super(AFL3, self).__init__()

        # A dictionary mapping from a (hex(start), hex(end)) tuple to the number of times this transition has been
        # observed globally
        self.wait_stash = 'no_interesting_transitions'

    def setup(self, pg):
        if self.wait_stash not in pg.stashes:
            pg.stashes[self.wait_stash] = []

    def step(self, pg, stash, **kwargs):

        # This handles the updates of the transitions
        super(AFL3, self).step(pg, stash, **kwargs)

        interesting_paths = set()

        # Every path should be considered for analysis I think, however we might want to re-evaluate if that is true.
        pg.move(self.wait_stash, stash)

        # Find the paths for each transition that have the highest number of runs for that transition
        max_transition_runners = {}
        min_transition_runners = {}
        for path in pg.stashes[stash]:
            # Update any transitions this path might be the deepest runner for
            for t in path.state.transition_tracker.local_transition_counts:
                count = path.state.transition_tracker.local_transition_counts[t]

                if t not in max_transition_runners or max_transition_runners[t][1] < count:
                    max_transition_runners[t] = (path, count)

                if t not in min_transition_runners or min_transition_runners[t][1] > count:
                    min_transition_runners[t] = (path, count)

        # Reactivate all most running transition paths
        for transition in max_transition_runners:
            interesting_paths.add(max_transition_runners[transition][0])

        for transition in min_transition_runners:
            interesting_paths.add(max_transition_runners[transition][0])

        # Stash away all non-interesting paths
        pg.move(stash, self.wait_stash, filter_func=lambda p: p not in interesting_paths)

        return pg
