from . import ExplorationTechnique

class Veritesting(ExplorationTechnique):
    """
    Enable veritesting. This technique, described in a paper[1] from CMU, attempts to address the problem of state
    explosions in loops by performing smart merging.

    [1] https://users.ece.cmu.edu/~aavgerin/papers/veritesting-icse-2014.pdf
    """
    def __init__(self, **options):
        super(Veritesting, self).__init__()
        self.options = options

    def step_path(self, path):
        vt = self.project.analyses.Veritesting(path, **self.options)
        if vt.result and vt.final_path_group:
            pg = vt.final_path_group
            pg.stash(from_stash='deviated', to_stash='active')
            pg.stash(from_stash='successful', to_stash='active')
            return pg.active, pg.stashes.get('unconstrained', []), pg.stashes.get('unsat', []), [], []
        return None
