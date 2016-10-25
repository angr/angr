from collections import defaultdict

import simuvex

from . import ExplorationTechnique

class AFL(ExplorationTechnique):
    """
    AFL-inspired exploration technique.

    This will keep advancing paths that so long as they keep producing new unseen control flow transitions. Once it runs
    out it will restart with all paths and again prune them while they do not produce new transitions until no paths are
    left over. Then it returns.
    """
    def __init__(self):
        super(AFL, self).__init__()

        # A dictionary mapping from a (hex(start), hex(end)) tuple to the number of times this transition has been
        # observed globally
        self.global_transition_count = defaultdict(int)
        self.wait_stash = 'no_interesting_transitions'

    def setup(self, pg):
        if self.wait_stash not in pg.stashes:
            pg.stashes[self.wait_stash] = []

    def step(self, pg, stash, **kwargs):

        pg = pg.step(stash=stash, **kwargs)

        active_paths = set()

        # Update transition trackers
        for path in pg.stashes[stash]:

            if len(path.addr_trace) < 1:
                active_paths.add(path)
                continue

            start = hex(path.addr_trace[-1])
            end = hex(path.addr)

            # Update path transition tracker
            path.state.transition_tracker.register_transition((start, end))
            # Update global transition_tracker
            self.global_transition_count[(start, end)] += 1

        # Every path should be considered for analysis I think, however we might want to re-evaluate if that is true.
        pg.move(self.wait_stash, stash)

        # Find the paths for each transition that have the highest number of runs for that transition
        max_transition_paths = {}
        for path in pg.stashes[stash]:
            # Update any transitions this path might be the deepest runner for
            for t in path.state.transition_tracker.transition_counts:
                count = path.state.transition_tracker.transition_counts[t]

                if t not in max_transition_paths or max_transition_paths[t][1] < count:
                    max_transition_paths[t] = (path, count)

        # Reactivate all most running transition paths
        for transition in max_transition_paths:
            active_paths.add(max_transition_paths[transition][0])

        inactive = filter(lambda p: p is not None, [None if p in active_paths else p for p in pg.stashes[stash]])
        scored_paths = sorted(inactive, key=lambda p: p.state.transition_tracker.transition_score, reverse=True)

        # Add as many paths based on scoring as the previous mechanisms did
        new_additions = set(scored_paths[:len(active_paths)])
        active_paths.update(new_additions)

        # Stash away all non-interesting paths
        pg.move(stash, self.wait_stash, filter_func=lambda p: p not in active_paths)

        return pg
