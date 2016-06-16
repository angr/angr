from . import ExplorationTechnique

class DFS(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """
    def setup(self, pg):
        if 'deferred' not in pg.stashes:
            pg.stashes['deferred'] = []

    def step(self, pg, stash, **kwargs):

        pg = pg.step(stash=stash, **kwargs)
        if len(pg.stashes[stash]) > 1:
            pg.stashes['deferred'].extend(pg.stashes[stash][1:])
            del pg.stashes[stash][1:]

        if len(pg.stashes[stash]) == 0:
            if len(pg.stashes['deferred']) == 0:
                return pg
            i, deepest = max(enumerate(pg.stashes['deferred']), key=lambda l: len(l[1].trace))
            pg.stashes['deferred'].pop(i)
            pg.stashes[stash].append(deepest)

        return pg
