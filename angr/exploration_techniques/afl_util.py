
def find_unique_transition_path(transition_to_path_mapping):
    shortest_list = min(transition_to_path_mapping.values(), key=len)
    return shortest_list[0] if len(shortest_list) == 1 else None


def find_most_covering_path(transition_to_path_mapping):
    path_to_transition_mapping = {}
    for t, path_list in transition_to_path_mapping.items():
        for path in path_list:
            path_to_transition_mapping.setdefault(path, []).append(t)

    most_covering_path = max(path_to_transition_mapping.items(), key=lambda item: len(item[1]))[0]
    return most_covering_path


def find_least_covering_path(transition_to_path_mapping):
    path_to_transition_mapping = {}
    for t, path_list in transition_to_path_mapping.items():
        for path in path_list:
            path_to_transition_mapping.setdefault(path, []).append(t)

    least_covering_path = min(path_to_transition_mapping.items(), key=lambda item: len(item[1]))[0]
    return least_covering_path


def approximate_best_path_set_cover(self, transition_to_covering_paths_mapping):
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


def find_min_max_transition_runners(pg, stash):
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

    return min_transition_runners, max_transition_runners
