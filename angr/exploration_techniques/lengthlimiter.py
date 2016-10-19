from . import ExplorationTechnique

class LengthLimiter(ExplorationTechnique):
    """
    Length limiter on paths.
    """

    def __init__(self, max_length, drop=False):
        super(LengthLimiter, self).__init__()
        self._max_length = max_length
        self._drop = drop

    def _filter(self, p):
        return p.weighted_length > self._max_length

    def step(self, pg, stash, **kwargs):
        pg = pg.step(stash=stash, **kwargs)
        pg.move('active', '_DROP' if self._drop else 'cut', self._filter)
        return pg
