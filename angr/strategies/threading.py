import concurrent.futures

from . import Strategy

class Threading(Strategy):
    def __init__(self, threads=8):
        super(Threading, self).__init__()
        self.threads = threads
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)

    def step(self, pg, stash, **kwargs):
        counts = [0]*self.threads
        def counts_of(i):
            out = counts[i]
            counts[i] = out + 1
            return out

        tasks = {}
        for x in xrange(self.threads):
            # construct new pg with lists w/ object identity
            # move every nth thread into a unique thread-local list
            # this means that threads won't trample each other's hooks
            # but can still negotiate over shared resources

            tpg = pg.copy(stashes=dict(pg.stashes))
            tpg._immutable = False
            tpg.stashes['threadlocal'] = []
            tpg.move(stash, 'threadlocal', lambda path: counts_of(x) % self.threads == x)
            tasks[self.executor.submit(tpg.step, stash='threadlocal', **kwargs)] = tpg

        pg.stashes[stash] = []
        for f in concurrent.futures.as_completed(tasks):
            pg.stashes[stash].extend(tasks[f].threadlocal)

        return pg

