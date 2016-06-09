from . import Strategy

class LoopLimiter(Strategy):
    def __init__(self, count=5, discard_stash='spinning'):
        super(LoopLimiter, self).__init__()
        self.count = count
        self.discard_stash = discard_stash

    def step(self, pg, stash, **kwargs):
        pg = pg.step(stash=stash, **kwargs).move(stash, self.discard_stash,
                lambda path: path.detect_loops() >= self.count)
        if len(pg.stashes[stash]) == 0 and len(pg.stashes[self.discard_stash]) > 0:
            pg.stashes[stash].append(pg.stashes[self.discard_stash].pop())
        return pg

