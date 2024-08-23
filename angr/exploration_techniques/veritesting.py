from __future__ import annotations
from . import ExplorationTechnique

from ..sim_options import EFFICIENT_STATE_MERGING


class Veritesting(ExplorationTechnique):
    """
    Enable veritesting. This technique, described in a paper[1] from CMU, attempts to address the problem of state
    explosions in loops by performing smart merging.

    [1] https://users.ece.cmu.edu/~aavgerin/papers/veritesting-icse-2014.pdf
    """

    def __init__(self, **options):
        super().__init__()
        self.options = options

    def step_state(self, simgr, state, successor_func=None, **kwargs):
        if EFFICIENT_STATE_MERGING not in state.options:
            state.options.add(EFFICIENT_STATE_MERGING)

        vt = self.project.analyses.Veritesting(state, **self.options)
        if vt.result and vt.final_manager:
            simgr2 = vt.final_manager
            simgr2.stash(from_stash="deviated", to_stash="active")
            simgr2.stash(from_stash="successful", to_stash="active")

            return {
                "active": simgr2.active,
                "unconstrained": simgr2.stashes.get("unconstrained", []),
                "unsat": simgr2.stashes.get("unsat", []),
                "pruned": simgr2.stashes.get("pruned", []),
                "errored": simgr2.errored,
            }

        return simgr.step_state(state, successor_func=successor_func, **kwargs)
