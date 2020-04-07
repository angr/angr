# pylint: disable=cell-var-from-loop
import concurrent.futures

from . import ExplorationTechnique

class Threading(ExplorationTechnique):
    """
    Enable multithreading.

    This is only useful in paths where a lot of time is taken inside z3, doing constraint solving.
    This is because of python's GIL, which says that only one thread at a time may be executing python code.
    """
    def __init__(self, threads=8):
        super(Threading, self).__init__()
        self.threads = threads
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)

    def step(self, simgr, stash='active', **kwargs):
        counts = [0]*self.threads
        def counts_of(i):
            out = counts[i]
            counts[i] = out + 1
            return out

        tasks = {}
        for x in range(self.threads):
            # construct new simgr with lists w/ object identity
            # move every nth thread into a unique thread-local list
            # this means that threads won't trample each other's hooks
            # but can still negotiate over shared resources

            tsimgr = simgr.copy(stashes=dict(simgr.stashes))
            tsimgr.stashes['threadlocal'] = []
            tsimgr.move(stash, 'threadlocal', lambda path: counts_of(x) % self.threads == x)
            tasks[self.executor.submit(tsimgr.step, stash='threadlocal', **kwargs)] = tsimgr

        for f in concurrent.futures.as_completed(tasks):
            simgr.populate(stash, tasks[f].threadlocal)

        return simgr
