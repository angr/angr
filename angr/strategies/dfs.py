from . import Strategy

class DFS(Strategy):
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
