from __future__ import annotations
from . import ExplorationTechnique


class StubStasher(ExplorationTechnique):
    """
    Stash states that reach a stub SimProcedure.
    """

    @staticmethod
    def post_filter(state):
        hook = state.project.hooked_by(state.addr)
        return hook and hook.is_stub

    def step(self, simgr, stash="active", **kwargs):
        simgr.step(stash=stash, **kwargs)
        simgr.move(stash, "stub", filter_func=self.post_filter)
        return simgr
