#!/usr/bin/env python

import multiprocessing
#import concurrent.futures
import logging

l = logging.getLogger("angr.surveyor")

STOP_RUNS = False
PAUSE_RUNS = False

def enable_singlestep():
    global PAUSE_RUNS
    PAUSE_RUNS = True


def disable_singlestep():
    global PAUSE_RUNS
    PAUSE_RUNS = False


def stop_analyses():
    global STOP_RUNS
    STOP_RUNS = True


def resume_analyses():
    global STOP_RUNS
    STOP_RUNS = False


import signal


def handler(signum, frame):  # pylint: disable=W0613,
    if signum == signal.SIGUSR1:
        stop_analyses()
    elif signum == signal.SIGUSR2:
        enable_singlestep()


signal.signal(signal.SIGUSR1, handler)
signal.signal(signal.SIGUSR2, handler)


class Surveyors(object):
    def _surveyor(self, _, val, *args, **kwargs):
        """
        Calls a surveyor and adds result to the .started list
        """
        surveyor = val
        # Call __init__ of chosen surveyor
        return surveyor(self._p, *args, **kwargs)

    def __init__(self, p, all_surveyors):
        self._p = p
        self._all_surveyors = all_surveyors
        utils.bind_dict_as_funcs(self, all_surveyors, self._surveyor)

    def __getstate__(self):
        return self._p, self._all_surveyors

    def __setstate__(self, s):
        p, all_surveyors = s
        self.__init__(p, all_surveyors)


class Surveyor(object):
    """
    The surveyor class eases the implementation of symbolic analyses. This
    provides a base upon which analyses can be implemented. It has the
    following overloadable functions/properties:

        done: returns True if the analysis is done (by default, this is when
              self.active is empty)
        run: runs a loop of tick()ing and spill()ming until self.done is
             True
        tick: ticks all paths forward. The default implementation calls
              tick_path() on every path
        tick_path: moves a provided path forward, returning a set of new
                   paths
        spill: spills all paths, in-place. The default implementation first
              calls spill_path() on every path, then spill_paths() on the
              resulting sequence, then keeps the rest.
        spill_path: returns a spilled sequence of paths from a provided
                   sequence of paths
        spill_paths: spills a path

    An analysis can overload either the specific sub-portions of surveyor
    (i.e, the tick_path and spill_path functions) or bigger and bigger pieces
    to implement more and more customizeable analyses.

    Surveyor provides at lest the following members:

        active - the paths that are still active in the analysis
        deadended - the paths that are still active in the analysis
        spilled - the paths that are still active in the analysis
        errored - the paths that have at least one error-state exit
        pruned - paths that were pruned because their ancestors were unsat
        unconstrained - paths that have a successor with an unconstrained instruction pointer
    """

    path_lists = ['active', 'deadended', 'spilled', 'errored', 'unconstrained', 'suspended', 'pruned' ] # TODO: what about errored? It's a problem cause those paths are duplicates, and could cause confusion...

    def __init__(self, project, start=None, max_active=None, max_concurrency=None, pickle_paths=None,
                 save_deadends=None):
        """
        Creates the Surveyor.

            @param project: the angr.Project to analyze
            @param starts: an exit to start the analysis on
            @param starts: the exits to start the analysis on. If neither start nor
                           starts are given, the analysis starts at p.initial_exit()
            @param max_active: the maximum number of paths to explore at a time
            @param max_concurrency: the maximum number of worker threads
            @param pickle_paths: pickle spilled paths to save memory
            @param save_deadends: save deadended paths
        """

        self._project = project
        if project._parallel:
            self._max_concurrency = multiprocessing.cpu_count() if max_concurrency is None else max_concurrency
        else:
            self._max_concurrency = 1
        self._max_active = multiprocessing.cpu_count() if max_active is None else max_active
        self._pickle_paths = False if pickle_paths is None else pickle_paths
        self._save_deadends = True if save_deadends is None else save_deadends

        # the paths
        self.active = []
        self.deadended = []
        self.spilled = []
        self.errored = []
        self.pruned = []
        self.suspended = []
        self.unconstrained = []

        self.split_paths = {}
        self._current_step = 0
        self._heirarchy = PathHeirarchy()

        if isinstance(start, Path):
            self.active.append(start)
        elif isinstance(start, (tuple, list, set)):
            self.active.extend(start)
        elif start is None:
            self.active.append(self._project.path_generator.entry_point())
        else:
            raise AngrError('invalid "start" argument')

    #
    # Quick list access
    #

    @property
    def _a(self):
        return self.active[0]

    @property
    def _d(self):
        return self.deadended[0]

    @property
    def _spl(self):
        return self.spilled[0]

    @property
    def _e(self):
        return self.errored[0]

    #
    # Overall analysis.
    #

    def pre_tick(self):
        """
        Provided for analyses to use for pre-tick actions.
        """
        pass

    def post_tick(self):
        """
        Provided for analyses to use for pre-tick actions.
        """
        pass

    def step(self):
        """
        Takes one step in the analysis (called by run()).
        """

        self.pre_tick()
        self.tick()
        #self.filter()
        self.spill()
        self.post_tick()
        self._current_step += 1

        l.debug("After iteration: %s", self)
        return self

    def run(self, n=None):
        """
        Runs the analysis through completion (until done() returns True) or,
        if n is provided, n times.

            @params n: the maximum number of ticks
            @returns itself for chaining
        """
        global STOP_RUNS, PAUSE_RUNS  # pylint: disable=W0602,

        while not self.done and (n is None or n > 0):
            self.step()

            if STOP_RUNS:
                l.warning("%s stopping due to STOP_RUNS being set.", self)
                l.warning("... please call resume_analyses() and then this.run() if you want to resume execution.")
                break

            if PAUSE_RUNS:
                l.warning("%s pausing due to PAUSE_RUNS being set.", self)
                l.warning("... please call disable_singlestep() before continuing if you don't want to single-step.")

                try:
                    import ipdb as pdb  # pylint: disable=F0401,
                except ImportError:
                    import pdb
                pdb.set_trace()

            if n is not None:
                n -= 1
        return self

    @property
    def done(self):
        """
        True if the analysis is done.
        """
        return len(self.active) == 0

    #
    # Utility functions.
    #

    def __repr__(self):
        return "%d active, %d spilled, %d deadended, %d errored, %d unconstrained" % (
            len(self.active), len(self.spilled), len(self.deadended), len(self.errored), len(self.unconstrained))

    #
    # Analysis progression
    #

    def tick(self):
        """
        Takes one step in the analysis. Typically, this moves all active paths
        forward.

            @returns itself, for chaining
        """
        new_active = []

        #with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_concurrency) as executor:
        #   future_to_path = {executor.submit(self.safe_tick_path, p): p for p in self.active}
        #   for future in concurrent.futures.as_completed(future_to_path):
        #       p = future_to_path[future]
        #       successors = future.result()

        for p in self.active:
            if p.errored:
                if isinstance(p.error, PathUnreachableError):
                    self.pruned.append(p)
                else:
                    self._heirarchy.unreachable(p)
                    self.errored.append(p)
                continue
            if len(p.successors) == 0 and len(p.unconstrained_successor_states) == 0:
                l.debug("Path %s has deadended.", p)
                self.suspend_path(p)
                self.deadended.append(p)
            else:
                successors = self.tick_path(p)
                new_active.extend(successors)

            if len(p.unconstrained_successor_states) > 0:
                self.unconstrained.append(p)

        self.active = new_active
        return self

    def tick_path(self, p):
        """
        Ticks a single path forward. Returns a sequence of successor paths.
        """
        l.debug("Ticking path %s", p)
        self._heirarchy.add_successors(p, p.successors)

        l.debug("... path %s has produced %d successors.", p, len(p.successors))
        l.debug("... addresses: %s", [ "0x%x"%s.addr for s in p.successors ])
        filtered_successors = self.filter_paths(p.successors)
        l.debug("Remaining: %d successors out of %d", len(filtered_successors), len(p.successors))

        # track the path ID for visualization
        if len(filtered_successors) == 1: filtered_successors[0].path_id = p.path_id
        else: self.split_paths[p.path_id] = [sp.path_id for sp in filtered_successors]

        return filtered_successors

    def prune(self):
        """
        Prune unsat paths.
        """

        for p in self.active:
            if not p.state.satisfiable():
                self._heirarchy.unreachable(p)
                self.active.remove(p)
                self.pruned.append(p)

        for p in self.spilled:
            if not p.state.satisfiable():
                self._heirarchy.unreachable(p)
                self.spilled.remove(p)
                self.pruned.append(p)

    ###
    ### Path termination.
    ###

    def filter_path(self, p):  # pylint: disable=W0613,R0201
        """
        Returns True if the given path should be kept in the analysis, False
        otherwise.
        """
        return True

    def filter_paths(self, paths):
        """
        Given a list of paths, returns filters them and returns the rest.
        """
        return [p for p in paths if self.filter_path(p)]

    #def filter(self):
    #   """
    #   Filters the active paths, in-place.
    #   """
    #   old_active = self.active[ :: ]

    #   l.debug("before filter: %d paths", len(self.active))
    #   self.active = self.filter_paths(self.active)
    #   l.debug("after filter: %d paths", len(self.active))

    #   for a in old_active:
    #       if a not in self.active:
    #           self.deadended.append(a)

    ###
    ### State explosion control (spilling paths).
    ###

    def path_comparator(self, a, b):  # pylint: disable=W0613,R0201
        """
        This function should compare paths a and b, to determine which should
        have a higher priority in the analysis. It's used as the cmp argument
        to sort.
        """
        return 0

    def prioritize_paths(self, paths):
        """
        This function is called to sort a list of paths, to prioritize
        the analysis of paths. Should return a list of paths, with higher-
        priority paths first.
        """

        paths.sort(cmp=self.path_comparator)
        return paths

    def spill_paths(self, active, spilled):  # pylint: disable=R0201
        """
        Called with the currently active and spilled paths to spill some
        paths. Should return the new active and spilled paths.
        """

        l.debug("spill_paths received %d active and %d spilled paths.", len(active), len(spilled))
        prioritized = self.prioritize_paths(active + spilled)
        new_active = prioritized[:self._max_active]
        new_spilled = prioritized[self._max_active:]
        l.debug("... %d active and %d spilled paths.", len(new_active), len(new_spilled))
        return new_active, new_spilled

    def spill(self):
        """
        Spills/unspills paths, in-place.
        """
        new_active, new_spilled = self.spill_paths(self.active, self.spilled)

        num_suspended = 0
        num_resumed = 0

        for p in new_active:
            if p in self.spilled:
                num_resumed += 1
                #p.resume(self._project)

        for p in new_spilled:
            if p in self.active:
                num_suspended += 1
                self.suspend_path(p)

        l.debug("resumed %d and suspended %d", num_resumed, num_suspended)

        self.active, self.spilled = new_active, new_spilled

    def suspend_path(self, p): #pylint:disable=no-self-use
        """
        Suspends and returns a state.

        @param p: the path
        @returns the path
        """
        # TODO: Path doesn't provide suspend() now. What should we replace it with?
        # p.suspend(do_pickle=self._pickle_paths)
        return p

from .errors import AngrError, PathUnreachableError
from .path import Path
from .path_heirarchy import PathHeirarchy
from . import utils
