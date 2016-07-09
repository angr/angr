#!/usr/bin/env python

import multiprocessing
#import concurrent.futures
import logging
import weakref
import functools

l = logging.getLogger("angr.surveyor")

#
# Surveyor debugging
#

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

try:
    signal.signal(signal.SIGUSR1, handler)
    signal.signal(signal.SIGUSR2, handler)
except AttributeError:
    l.warning("Platform doesn't support SIGUSR")

# function that produces unpredictable results that should appease pylint's
# static analysis and stop giving us those awful errors!!!!

def dummy_func(*args, **kwargs):
    return args + list(kwargs)

#
# Surveyor list
#

class Surveyors(object):
    def __init__(self, project):
        self._project = project
        self.started = [ ]

        self.Explorer = dummy_func
        self.Caller = dummy_func
        self.Escaper = dummy_func

        for surveyor_name,surveyor in all_surveyors.items():
            setattr(self, surveyor_name, functools.partial(self._start_surveyor, surveyor))

    def _surveyor_finished(self, proxy):
        self.started.remove(proxy)

    def _start_surveyor(self, surveyor, *args, **kwargs):
        """
        Calls a surveyor and adds result to the .started list. See
        the arguments for the specific surveyor for its documentation.
        """
        s = surveyor(self._project, *args, **kwargs)
        self.started.append(weakref.proxy(s, self._surveyor_finished))
        return s

    def __getstate__(self):
        return self._project

    def __setstate__(self, s):
        self.__init__(s)

class Surveyor(object):
    """
    The surveyor class eases the implementation of symbolic analyses. This
    provides a base upon which analyses can be implemented.

    Surveyors provide at least the following members:

    :ivar active:           The paths that are still active in the analysis.
    :ivar deadended:        The paths that are still active in the analysis.
    :ivar spilled:          The paths that are still active in the analysis.
    :ivar errored:          The paths that have at least one error-state exit.
    :ivar pruned:           The paths that were pruned because their ancestors were unsat.
    :ivar unconstrained:    The paths that have a successor with an unconstrained instruction pointer.

    A Surveryor has the following overloadable properties:

    :ivar done: returns True if the analysis is done (by default, this is when self.active is empty).
    :ivar run: runs a loop of tick()ing and spill()ing until self.done is True.
    :ivar tick: ticks all paths forward. The default implementation calls tick_path() on every path.

    A Surveyor has the following overloadable functions :

    :func:`tick_path` moves a provided path forward, returning a set of new paths.

    :func:`spill` spills all paths, in-place. The default implementation first calls :func:`spill_path` on every
    path, then :func:`spill_paths` on the resulting sequence, then keeps the rest.

    :func:`spill_path` returns a spilled sequence of paths from a provided sequence of paths.

    An analysis can overload either the specific sub-portions of surveyor
    (i.e, the tick_path and spill_path functions) or bigger and bigger pieces
    to implement more and more customizeable analyses.
    """

    # TODO: what about errored? It's a problem cause those paths are duplicates, and could cause confusion...
    path_lists = ['active', 'deadended', 'spilled', 'errored', 'unconstrained', 'suspended', 'pruned' ]
    def __init__(self, project, start=None, max_active=None, max_concurrency=None, pickle_paths=None,
                 save_deadends=None, enable_veritesting=False, veritesting_options=None, keep_pruned=None):
        """
        Creates the Surveyor.

        :param project:             the angr.Project to analyze.
        :param start:               a path (or set of paths) to start the analysis from
        :param max_active:          the maximum number of paths to explore at a time
        :param max_concurrency:     the maximum number of worker threads
        :param pickle_paths:        pickle spilled paths to save memory
        :param save_deadends:       save deadended paths
        :param enable_veritesting:  use static symbolic execution to speed up exploration
        :param veritesting_options: special options to be passed to Veritesting
        :param keep_pruned:         keep pruned unsat states
        """

        self._project = project
        self._max_concurrency = 1 if max_concurrency is None else max_concurrency
        self._max_active = multiprocessing.cpu_count() if max_active is None else max_active
        self._pickle_paths = False if pickle_paths is None else pickle_paths
        self._save_deadends = True if save_deadends is None else save_deadends
        self._keep_pruned = False  if keep_pruned is None else keep_pruned

        self._enable_veritesting = enable_veritesting
        self._veritesting_options = { } if veritesting_options is None else veritesting_options

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
        self._hierarchy = PathHierarchy()

        if isinstance(start, Path):
            self.active.append(start)
        elif isinstance(start, (tuple, list, set)):
            self.active.extend(start)
        elif start is None:
            self.active.append(self._project.factory.path())
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
        Runs the analysis through completion (until done() returns True) or, if n is provided, n times.

        :param n: the maximum number of ticks
        :returns: itself for chaining
        """
        global STOP_RUNS, PAUSE_RUNS  # pylint: disable=W0602,

        # We do a round of filtering first
        self.active = self.filter_paths(self.active)

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
        Takes one step in the analysis. Typically, this moves all active paths forward.

        :return: itself, for chaining
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
                    if self._keep_pruned:
                        self.pruned.append(p)
                else:
                    self._hierarchy.unreachable_path(p)
                    self._hierarchy.simplify()
                    self.errored.append(p)
                continue
            self._step_path(p)
            if len(p.successors) == 0 and len(p.unconstrained_successor_states) == 0:
                l.debug("Path %s has deadended.", p)
                self.suspend_path(p)
                self.deadended.append(p)
            else:
                if self._enable_veritesting: # and len(p.successors) > 1:
                    # Try to use Veritesting!
                    if hasattr(self, '_find') and hasattr(self, '_avoid'):
                        # pylint: disable=no-member
                        boundaries = [ ]
                        if self._find is not None:
                            boundaries.extend(list(self._find))
                        if self._avoid is not None:
                            boundaries.extend(list(self._avoid))
                        veritesting = self._project.analyses.Veritesting(p,
                                                                         boundaries=boundaries,
                                                                         **self._veritesting_options)
                    else:
                        veritesting = self._project.analyses.Veritesting(p,
                                                                         **self._veritesting_options)
                    if veritesting.result and veritesting.final_path_group:
                        pg = veritesting.final_path_group
                        self.deadended.extend(pg.deadended)
                        self.errored.extend(pg.errored)
                        successors = pg.successful + pg.deviated
                        for suc in successors:
                            l.info('Veritesting yields a new IP: 0x%x', suc.addr)
                        successors = self._tick_path(p, successors=successors)

                    else:
                        successors = self.tick_path(p)

                else:
                    successors = self.tick_path(p)
                new_active.extend(successors)

            if len(p.unconstrained_successor_states) > 0:
                self.unconstrained.append(p)

        self.active = new_active
        return self

    def _step_path(self, p):  #pylint:disable=no-self-use
        p.step()

    def _tick_path(self, p, successors=None):
        if successors is None:
            successors = p.successors

        l.debug("Ticking path %s", p)
        for s in successors:
            self._hierarchy.add_path(s)
        self._hierarchy.simplify()

        l.debug("... path %s has produced %d successors.", p, len(successors))
        l.debug("... addresses: %s", ["0x%x" % s.addr for s in successors])
        filtered_successors = self.filter_paths(successors)
        l.debug("Remaining: %d successors out of %d", len(filtered_successors), len(successors))

        # track the path ID for visualization
        if len(filtered_successors) == 1:
            filtered_successors[0].path_id = p.path_id
        else:
            self.split_paths[p.path_id] = [sp.path_id for sp in filtered_successors]

        return filtered_successors

    def tick_path(self, p):
        """
        Ticks a single path forward. Returns a sequence of successor paths.
        """

        return self._tick_path(p)

    def prune(self):
        """
        Prune unsat paths.
        """

        for p in list(self.active):
            if not p.reachable:
                self._hierarchy.unreachable_path(p)
                self._hierarchy.simplify()
                self.active.remove(p)
                self.pruned.append(p)

        for p in list(self.spilled):
            if not p.reachable:
                self._hierarchy.unreachable_path(p)
                self._hierarchy.simplify()
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

        :param p: the path
        :returns: the path
        """
        # TODO: Path doesn't provide suspend() now. What should we replace it with?
        # p.suspend(do_pickle=self._pickle_paths)
        p.state.downsize()
        return p

from .errors import AngrError, PathUnreachableError
from .path import Path
from .path_hierarchy import PathHierarchy
from .surveyors import all_surveyors
