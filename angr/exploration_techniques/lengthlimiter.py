from . import ExplorationTechnique

class LengthLimiter(ExplorationTechnique):
    """
    Length limiter on paths.
    """

    def __init__(self, max_length, drop=False):
        super(LengthLimiter, self).__init__()
        self._max_length = max_length
        self._drop = drop

    def _filter(self, s):
        return s.history.block_count > self._max_length

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        simgr.move('active', '_DROP' if self._drop else 'cut', self._filter)
        return simgr
