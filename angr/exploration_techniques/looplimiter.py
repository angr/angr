from . import ExplorationTechnique

class LoopLimiter(ExplorationTechnique):
    """
    Limit the number of loops a path may go through.
    Paths that exceed the loop limit are moved to a discard stash.

    Note that this uses the default detect_loops method from Path, which approximates loop
    counts by counting the number of times each basic block is executed in a given stack frame.
    """
    def __init__(self, count=5, discard_stash='spinning'):
        super(LoopLimiter, self).__init__()
        self.count = count
        self.discard_stash = discard_stash

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        simgr = simgr.move(stash, self.discard_stash, lambda path: path.detect_loops() >= self.count)
        if len(simgr.stashes[stash]) == 0 and len(simgr.stashes[self.discard_stash]) > 0:
            simgr.stashes[stash].append(simgr.stashes[self.discard_stash].pop())
        return simgr

