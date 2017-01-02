from angr.exploration_techniques.afl_transition_tracker import SimTransitionTracker

from . import ExplorationTechnique


class AFLBase(ExplorationTechnique):
    """
    This exploration technique is the basis for all the AFL-inspired exploration techniques.

    It takes care of the transition tracking in the state so that the actual analysis can access this information.
    """

    def __init__(self):
        super(AFLBase, self).__init__()

    def setup(self, pg):
        super(AFLBase, self).setup(pg)

        for stash in pg.stashes:
            for path in pg.stashes[stash]:
                path.state.register_plugin('transition_tracker', SimTransitionTracker())


    def step(self, pg, stash, **kwargs):

        pg = pg.step(stash=stash, **kwargs)

        # Update transition trackers
        for path in pg.stashes[stash]:

            hex_starts = map(hex, path.history._addrs)
            hex_ends = map(hex, path.history._addrs)[1:] + [hex(path.addr)]
            transitions = zip(hex_starts, hex_ends)

            for transition in transitions:
                path.state.transition_tracker.register_transition(transition)

        return pg
