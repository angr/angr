#!/usr/bin/env python

from . import Path

import logging
l = logging.getLogger("angr.Surveyor")

class Surveyor(object):
    '''
    The surveyor class eases the implementation of symbolic analyses. This
    provides a base upon which analyses can be implemented. It has the
    following overloadable functions/properties:

        done: returns True if the analysis is done (by default, this is when
              self.active is empty)
        run: runs a loop of tick()ing and trim()ming until self.done is
             True
        tick: ticks all paths forward. The default implementation calls
              tick_path() on every path
        tick_path: moves a provided path forward, returning a set of new
                   paths
        trim: trims all paths, in-place. The default implementation first
              calls trim_path() on every path, then trim_paths() on the
              resulting sequence, then keeps the rest.
        trim_path: returns a trimmed sequence of paths from a provided
                   sequence of paths
        trim_paths: trims a path
    
    An analysis can overload either the specific sub-portions of surveyor
    (i.e, the tick_path and trim_path functions) or bigger and bigger pieces
    to implement more and more customizeable analyses.
    
    Surveyor provides at lest the following members:

        active - the paths that are still active in the analysis
        deadended - the paths that are still active in the analysis
        trimmed - the paths that are still active in the analysis
        errored - the paths that have at least one error-state exit
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
        self._max_concurrency = 10 if max_concurrency is None else max_concurrency

        # the paths
        self.active = [ ]
        self.deadended = [ ]
        self.trimmed = [ ]
        self.errored = [ ]

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

    def tick_path(self, p):
        '''
        Ticks a single path forward. This should return a sequence of successor
        paths.
        '''

        successors = p.continue_path()
        if len(p.errored) > 0:
            l.debug("Path %s has yielded %d errored exits.", p, len(p.errored))
            self.errored.append(p)
        if len(successors) == 0:
            l.debug("Path %s has deadended.", p)
            self.deadended.append(p)

        return successors

    def tick(self):
        '''
        Takes one step in the analysis. Typically, this moves all active paths
        forward.

            @returns itself, for chaining
        '''
        new_active = [ ]

        for p in self.active:
            new_active.extend(self.tick_path(p))

        self.active = new_active
        return self

    def trim_path(self, p): # pylint: disable=W0613,R0201
        '''
        Returns True if the given path should be trimmed (excluded from the
        active paths), False otherwise.
        '''
        return False

    def trim_paths(self, paths):
        '''
        Called to trim a sequence of paths. Should return the new sequence.
        '''
        self.trimmed += paths[self._max_concurrency:]
        return paths[:self._max_concurrency]

    def trim(self):
        '''
        Trims the active paths, in-place.
        '''
        l.debug("%s about to do individual trimming", self)
        new_active = [ p for p in self.active if not self.trim_path(p) ]
        l.debug("... individual trimming returned %d", len(new_active))
        new_active = self.trim_paths(new_active)
        l.debug("... final trimming returned %d", len(new_active))
        self.active = new_active

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
        return len(self.active) == 0

    def __str__(self):
        return "%d active, %d trimmed, %d deadended" % (len(self.active), len(self.trimmed), len(self.deadended))
