from . import ExplorationTechnique
import random

class DFS(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """

    def __init__(self):
        super(DFS, self).__init__()
        self._random = random.Random()
        self._random.seed(10)

    def setup(self, pg):
        if 'deferred' not in pg.stashes:
            pg.stashes['deferred'] = []

    def step(self, pg, stash, **kwargs):
        pg = pg.step(stash=stash, **kwargs)
        if len(pg.stashes[stash]) > 1:
            self._random.shuffle(pg.stashes[stash])
            pg.split(from_stash=stash, to_stash='deferred', limit=1)

        if len(pg.stashes[stash]) == 0:
            if len(pg.stashes['deferred']) == 0:
                return pg
            pg.stashes[stash].append(pg.stashes['deferred'].pop())

        return pg
