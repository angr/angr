from collections import defaultdict

from angr.exploration_techniques import afl_util

from .afl_base import AFLBase
import random

class AFL2(AFLBase):
    """
    AFL-inspired exploration technique.

    This will keep advancing paths that so long as they keep producing new unseen control flow transitions. Once it runs
    out it will restart with all paths and again prune them while they do not produce new transitions until no paths are
    left over. Then it returns.
    """
    def __init__(self, explore_path_reorder_function=lambda pg, path_list: sorted(path_list, key=lambda p: p.state.transition_tracker.local_transition_score, reverse=False)):
        super(AFL2, self).__init__()

        # A dictionary mapping from a (hex(start), hex(end)) tuple to the number of times this transition has been
        # observed globally
        self.wait_stash = 'no_interesting_transitions'

        self.reorder_func = explore_path_reorder_function

    def setup(self, pg):
        super(AFL2, self).setup(pg)
        if self.wait_stash not in pg.stashes:
            pg.stashes[self.wait_stash] = []

    def step(self, pg, stash, **kwargs):

        # This handles the updates of the transitions
        super(AFL2, self).step(pg, stash, **kwargs)

        active_paths = set()

        # Every path should be considered for analysis I think, however we might want to re-evaluate if that is true.
        pg.move(self.wait_stash, stash)

        for path in pg.stashes[stash]:
            if len(path.addr_trace) < 1:
                active_paths.add(path)
                continue


        # Find the paths for each transition that have the highest number of runs for that transition
        transition_to_optimal_paths = {}
        transition_to_optimal_count = {}
        for path in pg.stashes[stash]:
            # Update any transitions this path might be the deepest runner for
            for t in path.state.transition_tracker.local_transition_counts:
                count = path.state.transition_tracker.local_transition_counts[t]

                if t not in transition_to_optimal_count or transition_to_optimal_count[t] < count:
                    transition_to_optimal_count[t] = count
                    transition_to_optimal_paths[t] = []

                if transition_to_optimal_count[t] == count:
                    transition_to_optimal_paths[t].append(path)

        # Reactivate all most running transition paths
        for path in afl_util.approximate_best_path_set_cover(transition_to_optimal_paths):
            active_paths.add(path)

        inactive = [p for p in pg.stashes[stash] if p not in active_paths]
        scored_paths_reordered = self.reorder_func(pg, inactive)

        new_additions = set(scored_paths_reordered[:min(len(inactive), len(active_paths))])
        active_paths.update(new_additions)

        # Stash away all non-interesting paths
        pg.move(stash, self.wait_stash, filter_func=lambda p: p not in active_paths)

        return pg
