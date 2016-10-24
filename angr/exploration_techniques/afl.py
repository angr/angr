from collections import defaultdict

from . import ExplorationTechnique

class AFL(ExplorationTechnique):
    """
    AFL-inspired exploration technique.

    This will keep advancing paths that so long as they keep producing new unseen control flow transitions. Once it runs
    out it will restart with all paths and again prune them while they do not produce new transitions until no paths are
    left over. Then it returns.
    """
    def setup(self, pg):
        # A dictionary mapping from one label_descriptor to a list of known successors
        self.global_transition_count = defaultdict(int)
        self.wait_stash = 'no_interesting_transitions'

        if self.wait_stash not in pg.stashes:
            pg.stashes[self.wait_stash] = []

    def step(self, pg, stash, **kwargs):

        pg = pg.step(stash=stash, **kwargs)

        def known_transition_stash_filter_func(path):
            if len(path.addr_trace) < 2:
                return False

            start = hex(path.addr_trace[-2])
            end = hex(path.addr_trace[-1])

            # Afl bucketization with uniqueness built-in
            is_interesting = self.global_transition_count[(start, end)] % 2 == 0
            self.global_transition_count[(start, end)] += 1
            should_be_stashed = not is_interesting
            return should_be_stashed

        pg.move(stash, self.wait_stash, filter_func=known_transition_stash_filter_func)

        if len(pg.stashes[stash]) == 0 and len(pg.stashes[self.wait_stash]) > 0:
            pg.move(self.wait_stash, stash)


        return pg
