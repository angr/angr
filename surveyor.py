#!/usr/bin/env python

from . import Path

import logging
l = logging.getLogger("angr.Surveyor")

class Surveyor(object):
    '''
    The surveyor class eases the implementation of symbolic analyses. Provides at
    lest the following members:

        active - the paths that are still active in the analysis
    '''

    def __init__(self, project, start=None, starts=None, max_concurrency=None):
        '''
        Creates the Surveyor.

            @param project: the angr.Project to analyze
            @param starts: an exit to start the analysis on
            @param starts: the exits to start the analysis on. If neither start nor
                           starts are given, the analysis starts at p.initial_exit()
            @param max_concurrency: the maximum number of paths to explore at a time
        '''

        self._project = project
        self.callback = project.sim_run
        self._max_concurrency = 10 if max_concurrency is None else max_concurrency

        # the paths
        self.active = [ ]
        self.deadended = [ ]
        self.trimmed = [ ]

        if start is not None:
            self.analyze_exit(start)

        if starts is not None:
            for e in starts:
                self.analyze_exit(e)

        if start is None and starts is None:
            self.analyze_exit(project.initial_exit())

    def active_exits(self, reachable=None, concrete=None, symbolic=None):
        all_exits = [ ]
        for p in self.active:
            all_exits += p.flat_exits(reachable=reachable, concrete=concrete, symbolic=symbolic)
        return all_exits

    def analyze_exit(self, e):
        self.active.append(Path(project=self._project, entry=e))

    def tick(self):
        '''
        Takes one step in the analysis. Typically, this moves all active paths
        forward.

            @returns itself for chaining
        '''
        new_active = [ ]

        for p in self.active:
            successors = p.continue_path()
            if len(successors) == 0:
                l.debug("Path %s has deadended.", p)
                self.deadended.append(p)
            else:
                new_active.extend(successors)

        self.active = new_active
        return self

    def trim(self):
        '''
        Called after tick() to trim the paths to control the concurrency level.
        '''
        self.trimmed += self.active[self._max_concurrency:]
        self.active = self.active[:self._max_concurrency]

    def run(self):
        '''
        Runs the analysis through completion (until done() returns True).

            @returns itself for chaining
        '''
        while not self.done:
            self.tick()
            self.trim()
            l.debug("After tick/trim: %s", self)
        return self

    @property
    def done(self):
        '''
        True if the analysis is done.
        '''
        pass

    def __str__(self):
        return "%d active, %d trimmed, %d deadended" % (len(self.active), len(self.trimmed), len(self.deadended))
