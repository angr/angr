from collections import defaultdict

import simuvex
from angr.exploration_techniques.state_plugin_variables import SimVariables

from .afl_base import AFLBase
import random

class AFL4(object):
    def __init__(self, explore_path_reorder_function=lambda pg, path_list: sorted(path_list, key=lambda p: p.state.transition_tracker.local_transition_score, reverse=False)):
        super(AFL4, self).__init__()

        # A dictionary mapping from a (hex(start), hex(end)) tuple to the number of times this transition has been
        # observed globally
        self.wait_stash = 'no_interesting_transitions'

        self.reorder_func = explore_path_reorder_function

    def setup(self, pg):

        if self.wait_stash not in pg.stashes:
            pg.stashes[self.wait_stash] = []

        for stash in pg.stashes:
            for path in pg.stashes[stash]:
                path.state.register_plugin('user', SimVariables())
                self.setup_path_variables(path)

    def setup_path_variables(self, path):
        path.user.locals['transition_counter'] = defaultdict(int)           # transition_counter[transition] += 1
        path.user.locals['last_seen'] = defaultdict(list)                   # last_seen[transition].append(trans_idx)
        path.user.locals['seen_distance_counter'] = defaultdict(defaultdict(int))  # seen_distances[transition][distance] += 1
        path.user.locals['uninteresting_transition_repeat_counter'] = 0     # unteresting_repeat_counter += 1,
                                                                            # uninteresting_repeat_counter < len(seen_distances][transition])

    def num_all_transitions(self, path):
        return len(path.addr_trace)

    def all_transitions(self, path):
        hex_starts = map(hex, path.addr_trace)
        hex_ends = map(hex, path.addr_trace[1:] + [path.addr])
        return zip(hex_starts, hex_ends)

    def num_new_transitions(self, path):
        return len(path.history._addrs)

    def new_transitions(self, path):
        all_hex_starts = map(hex, path.history._addrs)
        all_hex_ends = map(hex, path.history._addrs[1:] + [path.addr])
        return zip(all_hex_starts, all_hex_ends)


    def register_transition(self, pg, stash, path, idx, transition):
        if len(path.state.user.locals['last_seen']) > 0:
            distance = idx - path.state.user.locals['last_seen'][-1]
            path.state.user.locals['seen_distances'].add(distance)

        path.state.user.locals['last_seen'][transition].append(idx)


    def step(self, pg, stash, **kwargs):
        pg = pg.step(stash=stash, **kwargs)

        for path in pg.stashes[stash]:
            new_transitions_start_index = self.num_all_transitions(path) - self.num_new_transitions(path)
            for idx, transition in enumerate(self.new_transitions(path)):
                self.register_transition(pg, stash, path, new_transitions_start_index + idx, transition)

        # Every path should be considered for analysis I think, however we might want to re-evaluate if that is true.
        pg.move(self.wait_stash, stash)
        interesting_paths = set()

        for path in pg.stashes[stash]:
            if len(path.addr_trace) < 1:
                interesting_paths.add(path)
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
        for path in self._approximate_best_path_set_cover(transition_to_optimal_paths):
            active_paths.add(path)

        inactive = [p for p in pg.stashes[stash] if p not in active_paths]
        scored_paths_reordered = self.reorder_func(pg, inactive)

        new_additions = set(scored_paths_reordered[:min(len(inactive), len(active_paths))])
        active_paths.update(new_additions)

        # Stash away all non-interesting paths
        pg.move(stash, self.wait_stash, filter_func=lambda p: p not in active_paths)

        return pg
