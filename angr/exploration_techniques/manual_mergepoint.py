from __future__ import annotations
import logging

from . import ExplorationTechnique

l = logging.getLogger(name=__name__)


class ManualMergepoint(ExplorationTechnique):
    def __init__(self, address, wait_counter=10, prune=True):
        super().__init__()
        self.address = address
        self.wait_counter_limit = wait_counter
        self.prune = prune
        self.wait_counter = 0
        self.stash = f"merge_waiting_{self.address:#x}_{id(self):x}"
        self.filter_marker = f"skip_next_filter_{self.address:#x}"

    def setup(self, simgr):
        simgr.stashes[self.stash] = []

    def mark_nofilter(self, simgr, stash):
        for state in simgr.stashes[stash]:
            state.globals[self.filter_marker] = True

    def mark_okfilter(self, simgr, stash):
        for state in simgr.stashes[stash]:
            state.globals.pop(self.filter_marker)

    def step(self, simgr, stash="active", **kwargs):
        # ha ha, very funny, if this is being run on a single-step basis our filter probably misfired
        if len(simgr.stashes[self.stash]) == 1 and len(simgr.stashes[stash]) == 0:
            simgr = simgr.move(self.stash, stash)

        # perform all our analysis as a post-mortem on a given step
        stop_points = kwargs.pop("extra_stop_points", set())
        stop_points.add(self.address)
        simgr = simgr.step(stash=stash, extra_stop_points=stop_points, **kwargs)
        # self.mark_okfilter(simgr, stash)

        # do filtering
        new_stash = []
        for state in simgr.stashes[stash]:
            if self.filter_marker not in state.globals and state.addr == self.address:
                self.wait_counter = 0
                simgr.stashes[self.stash].append(state)
            else:
                new_stash.append(state)
        simgr.stashes[stash][:] = new_stash

        # nothing to do if there's no states waiting
        if len(simgr.stashes[self.stash]) == 0:
            return simgr

        # tick the counter
        self.wait_counter += 1

        # see if it's time to merge (out of active or hit the wait limit)
        if len(simgr.stashes[stash]) != 0 and self.wait_counter < self.wait_counter_limit:
            return simgr

        # self.mark_nofilter(simgr, self.stash)

        # only both merging if, you know, there's actually states to merge
        if len(simgr.stashes[self.stash]) == 1:
            simgr.move(self.stash, stash)
            return simgr

        # do the merge, keyed by unique callstack
        l.info("Merging %d states at %#x", len(simgr.stashes[self.stash]), self.address)
        num_unique = 0
        while len(simgr.stashes[self.stash]):
            num_unique += 1
            exemplar_callstack = simgr.stashes[self.stash][0].callstack
            simgr.move(self.stash, "merge_tmp", lambda s, ec=exemplar_callstack: s.callstack == ec)
            l.debug("...%d with unique callstack #%d", len(simgr.merge_tmp), num_unique)
            if len(simgr.merge_tmp) > 1:
                simgr = simgr.merge(stash="merge_tmp", prune=self.prune)
            simgr = simgr.move("merge_tmp", stash)

        return simgr
