from . import ExplorationTechnique

from ..sim_options import EFFICIENT_STATE_MERGING

class Veritesting(ExplorationTechnique):
    """
    Enable veritesting. This technique, described in a paper[1] from CMU, attempts to address the problem of state
    explosions in loops by performing smart merging.

    [1] https://users.ece.cmu.edu/~aavgerin/papers/veritesting-icse-2014.pdf
    """
    def __init__(self, **options):
        super(Veritesting, self).__init__()
        self.options = options

    def step_state(self, simgr, state, successor_func=None, **kwargs):

        if EFFICIENT_STATE_MERGING not in state.options:
            state.options.add(EFFICIENT_STATE_MERGING)

        vt = self.project.analyses.Veritesting(state, **self.options)
        if vt.result and vt.final_manager:
            simgr = vt.final_manager
            simgr.stash(from_stash='deviated', to_stash='active')
            simgr.stash(from_stash='successful', to_stash='active')

            return {
                    'active': simgr.active,
                    'unconstrained': simgr.stashes.get('unconstrained', []),
                    'unsat': simgr.stashes.get('unsat', []),
                    'pruned': simgr.stashes.get('pruned', []),
                    'errored': simgr.errored,
                    }

        return simgr.step_state(state, successor_func=successor_func, **kwargs)
