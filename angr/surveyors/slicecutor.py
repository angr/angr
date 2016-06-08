#!/usr/bin/env python

import logging
l = logging.getLogger("angr.surveyors.slicecutor")

from ..surveyor import Surveyor
from ..errors import AngrExitError

from collections import defaultdict

# pylint: disable=W0212,

#
# HappyGraph is just here for testing. Please ignore it!
#
class HappyGraph(object):
    def __init__(self, path = None, paths=None, strict=False):
        if not strict:
            self.jumps = defaultdict(lambda: False)
        else:
            self.jumps = { }

        if paths is None:
            paths = [ ]
        if path is not None:
            paths.append(path)

        for p in paths:
            for i in range(len(p.addr_trace) - 1):
                self.jumps[(p.addr_trace[i], p.addr_trace[i+1])] = True
            self.jumps[(p.addr_trace[-1], p.addr)] = True

        self._merge_points = [ ]

    def filter_path(self, path): # pylint: disable=W0613,R0201,
        return True

    def should_take_exit(self, src, dst): # pylint: disable=W0613,R0201,
        return self.jumps[(src, dst)]

    def get_whitelisted_statements(self, addr): # pylint: disable=W0613,R0201,
        return None

    def get_last_statement_index(self, addr): # pylint: disable=W0613,R0201,
        return None

    def merge_points(self, path): # pylint: disable=W0613,R0201,
        return self._merge_points

    def path_priority(self, path): # pylint: disable=W0613,R0201,
        return 1

class Slicecutor(Surveyor):
    """The Slicecutor is a surveyor that executes provided code slices."""

    def __init__(self, project, annotated_cfg, start=None, targets=None, max_concurrency=None, max_active=None,
                 max_loop_iterations=None, pickle_paths=None, merge_countdown=10):
        Surveyor.__init__(self, project, start=start, max_concurrency=max_concurrency, max_active=max_active, pickle_paths=pickle_paths)

        # the loop limiter
        self._max_loop_iterations = max_loop_iterations if max_loop_iterations else None

        # the project we're slicing up!
        self._project = project

        # the annotated cfg to determine what to execute
        self._annotated_cfg = annotated_cfg

        # these are paths that are taking exits that the annotated CFG does not
        # know about
        self.mysteries = [ ]

        # these are paths that we cut due to the slicing
        self.cut = [ ]

        # those that have reached one of our targets
        self.reached_targets = []

        if targets is not None:
            self._targets = targets
        else:
            self._targets = []

        # mergesanity!
        self._merge_candidates = defaultdict(list)
        self._merge_countdowns = { }
        self.merge_countdown = merge_countdown

    def filter_path(self, path):
        l.debug("Checking path %s for filtering...", path)
        if not self._annotated_cfg.filter_path(path):
            l.debug("... %s is cut by AnnoCFG explicitly.", path)
            self.cut.append(self.suspend_path(path))
            return False

        l.debug("... checking loop iteration limit")
        if self._max_loop_iterations is not None and path.detect_loops() > self._max_loop_iterations:
            l.debug("... limit reached")
            return False

        l.debug("... checking if %s should wait for a merge.", path)
        if path.addr in path._upcoming_merge_points:
            l.debug("... it should!")
            if path.addr not in self._merge_candidates:
                self._merge_candidates[path.addr] = [ ]

            self._merge_candidates[path.addr].append(path)
            self._merge_countdowns[path.addr] = self.merge_countdown
            return False

        return True

    def tick_path(self, path):
        path._upcoming_merge_points = self._annotated_cfg.merge_points(path)

        path_successors = Surveyor.tick_path(self, path)
        new_paths = [ ]

        mystery = False
        cut = False

        # No new paths if the current path is already the target
        if not path.errored and path.addr in self._targets:
            self.reached_targets.append(self.suspend_path(path))
            return []

        l.debug("%s ticking path %s, last run is %s", self, path, path.previous_run)
        for successor in path_successors:
            dst_addr = successor.addr
            l.debug("... checking exit to 0x%x from %s", dst_addr, path.previous_run)
            try:
                taken = self._annotated_cfg.should_take_exit(path.addr, dst_addr)
            except AngrExitError: # TODO: which exception?
                l.debug("... annotated CFG did not know about it!")
                mystery = True
                continue

            if taken:
                l.debug("... taking the exit.")
                new_paths.append(successor)
                # the else case isn't here, because the path should set errored in this
                # case and we'll catch it below
            else:
                l.debug("... not taking the exit.")
                cut = True

        if mystery: self.mysteries.append(self.suspend_path(path))
        if cut: self.cut.append(self.suspend_path(path))

        return new_paths

    def pre_tick(self):

        # Set whitelists and last statements
        for p in self.active:
            addr = p.state.se.exactly_n_int(p.state.ip, 1)[0]
            whitelist = self._annotated_cfg.get_whitelisted_statements(addr)
            last_stmt = self._annotated_cfg.get_last_statement_index(addr)
            p.stmt_whitelist = whitelist
            p.last_stmt = last_stmt

        done_addrs = [ ]
        for addr, count in self._merge_countdowns.iteritems():
            l.debug("Checking merge point 0x%x with countdown %d.", addr, count)
            if count == 0:
                to_merge = self._merge_candidates[addr]
                l.debug("... merging %d paths!", len(to_merge))

                if len(to_merge) > 1:
                    new_path = to_merge[0].merge(*(to_merge[1:]))
                else:
                    new_path = to_merge[0]

                new_path.extra_length += self.merge_countdown
                done_addrs.append(addr)
                self.active.append(new_path)
            else:
                self._merge_countdowns[addr] -= 1

        for d in done_addrs:
            del self._merge_candidates[d]
            del self._merge_countdowns[d]

    @property
    def done(self):
        return (len(self.active) + len(self._merge_countdowns)) == 0

    def _step_path(self, p):  #pylint:disable=no-self-use
        p.step(stmt_whitelist=p.stmt_whitelist, last_stmt=p.last_stmt)

    def path_comparator(self, a, b):
        if a.weighted_length != b.weighted_length:
            return b.weighted_length - a.weighted_length
        return a.addr_trace.count(a.addr_trace[-1]) - b.addr_trace.count(b.addr_trace[-1])
        #return self._annotated_cfg.path_priority(a) - self._annotated_cfg.path_priority(b)

    def __repr__(self):
        return "<Slicecutor with paths: %s, %d cut, %d mysteries, %d reached targets, %d waiting to merge>" % (Surveyor.__repr__(self), len(self.cut), len(self.mysteries), len(self.reached_targets), sum(len(i) for i in self._merge_candidates.values()))

from . import all_surveyors
all_surveyors['Slicecutor'] = Slicecutor
