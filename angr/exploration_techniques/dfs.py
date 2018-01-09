from . import ExplorationTechnique
import random

class DFS(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """

    def __init__(self, deferred_stash='deferred'):
        super(DFS, self).__init__()
        self._random = random.Random()
        self._random.seed(10)
        self.deferred_stash = deferred_stash

    def setup(self, pg):
        if self.deferred_stash not in pg.stashes:
            pg.stashes[self.deferred_stash] = []

    def step(self, pg, stash, **kwargs):
        pg = pg._one_step(stash=stash, **kwargs)
        if len(pg.stashes[stash]) > 1:
            self._random.shuffle(pg.stashes[stash])
            pg.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)

        if len(pg.stashes[stash]) == 0:
            if len(pg.stashes[self.deferred_stash]) == 0:
                return pg
            pg.stashes[stash].append(pg.stashes[self.deferred_stash].pop())

        return pg
