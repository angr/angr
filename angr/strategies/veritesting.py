from . import Strategy

class Veritesting(Strategy):
    def __init__(self, **options):
        super(Veritesting, self).__init__(self)
        self.options = options

    def step_path(self, path):
        vt = self.project.analyses.Veritesting(path, **self.options)
        if vt.result and vt.final_path_group:
            pg = vt.final_path_group
            pg.stash(from_stash='deviated', to_stash='active')
            pg.stash(from_stash='successful', to_stash='active')
            return pg.active, pg.stashes.get('unconstrained', []), pg.stashes.get('unsat', []), [], []
        return None
