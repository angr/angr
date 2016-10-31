from collections import defaultdict

import simuvex

from . import ExplorationTechnique

class AFLBase(ExplorationTechnique):
    """
    This exploration technique is the basis for all the AFL-inspired exploration techniques.

    It takes care of the transition tracking in the state so that the actual analysis can access this information.
    """
    def __init__(self):
        super(AFLBase, self).__init__()

    def _find_unique_transition_path(self, transition_to_path_mapping):
        shortest_list = min(transition_to_path_mapping.values(), key=len)
        return shortest_list[0] if len(shortest_list) == 1 else None

    def _find_most_covering_path(self, transition_to_path_mapping):
        path_to_transition_mapping = {}
        for t, path_list in transition_to_path_mapping.items():
            for path in path_list:
                path_to_transition_mapping.setdefault(path, []).append(t)

        most_covering_path = max(path_to_transition_mapping.items(), key=lambda item: len(item[1]))[0]
        return most_covering_path

    def _approximate_best_path_set_cover(self, transition_to_covering_paths_mapping):
        cover_paths = set()

        mapping = transition_to_covering_paths_mapping.copy()

        while len(mapping) > 0:
            # Add paths that have to be present
            new_path = self._find_unique_transition_path(mapping)
            if new_path is None:
                # Otherwise add the most effective path (greedy)
                new_path = self._find_most_covering_path(mapping)

            # Remove any transitions that are already covered by this path
            mapping = {t: p_list for t, p_list in mapping.items() if new_path not in p_list}

            yield new_path


    def step(self, pg, stash, **kwargs):

        pg = pg.step(stash=stash, **kwargs)

        # Update transition trackers
        for path in pg.stashes[stash]:

            hex_starts = map(hex, path.history._addrs)
            hex_ends = map(hex, path.history._addrs)[1:] + [hex(path.addr)]
            transitions = zip(hex_starts, hex_ends)

            for transition in transitions:
                path.state.transition_tracker.register_transition(transition)

        return pg
    
