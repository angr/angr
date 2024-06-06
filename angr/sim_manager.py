from __future__ import annotations

import sys
import itertools
import types
from collections import defaultdict
import logging
from types import TracebackType

import claripy
import mulpyplexer

from .misc.hookset import HookSet
from .misc.ux import once
from .misc.picklable_lock import PicklableLock
from .errors import SimError, SimMergeError
from .sim_state import SimState
from .state_hierarchy import StateHierarchy
from .errors import AngrError, SimUnsatError, SimulationManagerError
from .sim_options import LAZY_SOLVES
from .state_plugins.sim_event import resource_event

l = logging.getLogger(name=__name__)


class SimulationManager:
    """
    The Simulation Manager is the future future.

    Simulation managers allow you to wrangle multiple states in a slick way. States are organized into "stashes", which
    you can step forward, filter, merge, and move around as you wish. This allows you to, for example, step two
    different stashes of states at different rates, then merge them together.

    Stashes can be accessed as attributes (i.e. .active).
    A mulpyplexed stash can be retrieved by prepending the name with `mp_`, e.g. `.mp_active`.
    A single state from the stash can be retrieved by prepending the name with `one_`, e.g. `.one_active`.

    Note that you shouldn't usually be constructing SimulationManagers directly - there is a convenient shortcut for
    creating them in ``Project.factory``: see :class:`angr.factory.AngrObjectFactory`.

    The most important methods you should look at are ``step``, ``explore``, and ``use_technique``.

    :param project:         A Project instance.
    :type project:          angr.project.Project
    :param stashes:         A dictionary to use as the stash store.
    :param active_states:   Active states to seed the "active" stash with.
    :param hierarchy:       A StateHierarchy object to use to track the relationships between states.
    :param resilience:      A set of errors to catch during stepping to put a state in the ``errore`` list.
                            You may also provide the values False, None (default), or True to catch, respectively,
                            no errors, all angr-specific errors, and a set of many common errors.
    :param save_unsat:      Set to True in order to introduce unsatisfiable states into the ``unsat`` stash instead
                            of discarding them immediately.
    :param auto_drop:       A set of stash names which should be treated as garbage chutes.
    :param completion_mode: A function describing how multiple exploration techniques with the ``complete``
                            hook set will interact. By default, the builtin function ``any``.
    :param techniques:      A list of techniques that should be pre-set to use with this manager.
    :param suggestions:     Whether to automatically install the Suggestions exploration technique. Default True.

    :ivar errored:          Not a stash, but a list of ErrorRecords. Whenever a step raises an exception that we catch,
                            the state and some information about the error are placed in this list. You can adjust the
                            list of caught exceptions with the `resilience` parameter.
    :ivar stashes:          All the stashes on this instance, as a dictionary.
    :ivar completion_mode:  A function describing how multiple exploration techniques with the ``complete`` hook set
                            will interact. By default, the builtin function ``any``.
    """

    ALL = "_ALL"
    DROP = "_DROP"

    _integral_stashes: tuple[str] = ("active", "stashed", "pruned", "unsat", "errored", "deadended", "unconstrained")

    def __init__(
        self,
        project,
        active_states=None,
        stashes=None,
        hierarchy=None,
        resilience=None,
        save_unsat=False,
        auto_drop=None,
        errored=None,
        completion_mode=any,
        techniques=None,
        suggestions=True,
        **kwargs,
    ):
        super().__init__()

        self._project = project
        self.completion_mode = completion_mode
        self._errored = []
        self._lock = PicklableLock()

        if stashes is None:
            stashes = self._create_integral_stashes()
        self._stashes: defaultdict[str, list[SimState]] = stashes
        self._hierarchy = StateHierarchy() if hierarchy is None else hierarchy
        self._save_unsat = save_unsat
        self._auto_drop = {
            SimulationManager.DROP,
        }
        self._techniques = []

        if resilience is None:
            self._resilience = (AngrError, SimError, claripy.ClaripyError)
        elif resilience is True:
            self._resilience = (
                AngrError,
                SimError,
                claripy.ClaripyError,
                KeyError,
                IndexError,
                TypeError,
                ValueError,
                ArithmeticError,
                MemoryError,
            )
        elif resilience is False:
            self._resilience = ()
        else:
            self._resilience = tuple(resilience)

        if suggestions:
            self.use_technique(Suggestions())

        # 8<----------------- Compatibility layer -----------------

        if auto_drop is None and not kwargs.pop("save_unconstrained", True):
            self._auto_drop |= {"unconstrained"}

        if kwargs.pop("veritesting", False):
            self.use_technique(Veritesting(**kwargs.get("veritesting_options", {})))
        kwargs.pop("veritesting_options", {})

        threads = kwargs.pop("threads", None)
        if threads is not None:
            self.use_technique(Threading(threads))

        if kwargs:
            raise TypeError("Unexpected keyword arguments: " + " ".join(kwargs))
        # ------------------ Compatibility layer ---------------->8

        if auto_drop:
            self._auto_drop |= set(auto_drop)

        if errored is not None:
            self._errored.extend(errored)

        if active_states:
            self._store_states("active", active_states)

        if techniques:
            for t in techniques:
                self.use_technique(t)

    def __repr__(self):
        stashes_repr = ", ".join(("%d %s" % (len(v), k)) for k, v in self._stashes.items() if len(v) != 0)
        if not stashes_repr:
            stashes_repr = "all stashes empty"
        errored_repr = " (%d errored)" % len(self.errored) if self.errored else ""
        return f"<SimulationManager with {stashes_repr}{errored_repr}>"

    def __getattr__(self, item):
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            return SimulationManager._fetch_states(self, stash=item)

    active: list[SimState]
    stashed: list[SimState]
    pruned: list[SimState]
    unsat: list[SimState]
    deadended: list[SimState]
    unconstrained: list[SimState]
    found: list[SimState]
    one_active: SimState
    one_stashed: SimState
    one_pruned: SimState
    one_unsat: SimState
    one_deadended: SimState
    one_unconstrained: SimState
    one_found: SimState

    def __dir__(self):
        return (
            list(self.__dict__)
            + dir(type(self))
            + list(self._stashes)
            + ["one_" + stash for stash in self._stashes]
            + ["mp_" + stash for stash in self._stashes]
        )

    @property
    def errored(self) -> list[ErrorRecord]:
        return self._errored

    @property
    def stashes(self) -> defaultdict[str, list[SimState]]:
        return self._stashes

    def mulpyplex(self, *stashes):
        """
        Mulpyplex across several stashes.

        :param stashes: the stashes to mulpyplex
        :return: a mulpyplexed list of states from the stashes in question, in the specified order
        """

        return mulpyplexer.MP(list(itertools.chain.from_iterable(self._stashes[s] for s in stashes)))

    def copy(self, deep=False):  # pylint: disable=arguments-differ
        """
        Make a copy of this simulation manager. Pass ``deep=True`` to copy all the states in it as well.

        If the current callstack includes hooked methods, the already-called methods will not be included in the copy.
        """
        simgr = SimulationManager(
            self._project,
            stashes=self._copy_stashes(deep=deep),
            hierarchy=self._hierarchy,
            resilience=self._resilience,
            auto_drop=self._auto_drop,
            completion_mode=self.completion_mode,
            errored=self._errored,
            suggestions=False,
        )
        HookSet.copy_hooks(self, simgr, ExplorationTechnique._hook_list)
        return simgr

    #
    #   ...
    #

    def use_technique(self, tech):
        """
        Use an exploration technique with this SimulationManager.

        Techniques can be found in :mod:`angr.exploration_techniques`.

        :param tech:    An ExplorationTechnique object that contains code to modify
                        this SimulationManager's behavior.
        :type tech:     ExplorationTechnique
        :return:        The technique that was added, for convenience
        """
        if not isinstance(tech, ExplorationTechnique):
            raise SimulationManagerError

        # XXX: as promised
        tech.project = self._project
        tech.setup(self)

        HookSet.install_hooks(self, **tech._get_hooks())
        self._techniques.append(tech)
        return tech

    def remove_technique(self, tech):
        """
        Remove an exploration technique from a list of active techniques.

        :param tech:    An ExplorationTechnique object.
        :type tech:     ExplorationTechnique
        """
        if not isinstance(tech, ExplorationTechnique):
            raise SimulationManagerError

        def _is_overriden(name):
            return getattr(tech, name).__code__ is not getattr(ExplorationTechnique, name).__code__

        overriden = filter(_is_overriden, ("step", "filter", "selector", "step_state", "successors"))
        hooks = {name: getattr(tech, name) for name in overriden}
        HookSet.remove_hooks(self, **hooks)

        self._techniques.remove(tech)
        return tech

    #
    #   ...
    #

    def explore(
        self,
        stash="active",
        n=None,
        find=None,
        avoid=None,
        find_stash="found",
        avoid_stash="avoid",
        cfg=None,
        num_find=1,
        avoid_priority=False,
        **kwargs,
    ):
        """
        Tick stash "stash" forward (up to "n" times or until "num_find" states are found), looking for condition "find",
        avoiding condition "avoid". Stores found states into "find_stash' and avoided states into "avoid_stash".

        The "find" and "avoid" parameters may be any of:

        - An address to find
        - A set or list of addresses to find
        - A function that takes a state and returns whether or not it matches.

        If an angr CFG is passed in as the "cfg" parameter and "find" is either a number or a list or a set, then
        any states which cannot possibly reach a success state without going through a failure state will be
        preemptively avoided.
        """
        num_find += len(self._stashes[find_stash]) if find_stash in self._stashes else 0
        tech = self.use_technique(
            Explorer(
                find,
                avoid,
                find_stash,
                avoid_stash,
                cfg,
                num_find,
                avoid_priority=avoid_priority,
            )
        )

        # Modify first Veritesting so that they can work together.
        deviation_filter_saved = None
        for t in self._techniques:
            if isinstance(t, Veritesting):
                deviation_filter_saved = t.options.get("deviation_filter", None)
                if deviation_filter_saved is not None:
                    t.options["deviation_filter"] = lambda s: tech.find(s) or tech.avoid(s) or deviation_filter_saved(s)
                else:
                    t.options["deviation_filter"] = lambda s: tech.find(s) or tech.avoid(s)
                break

        try:
            self.run(stash=stash, n=n, **kwargs)
        finally:
            self.remove_technique(tech)

        for t in self._techniques:
            if isinstance(t, Veritesting):
                if deviation_filter_saved is None:
                    del t.options["deviation_filter"]
                else:
                    t.options["deviation_filter"] = deviation_filter_saved
                break

        return self

    def run(self, stash="active", n=None, until=None, **kwargs):
        """
        Run until the SimulationManager has reached a completed state, according to
        the current exploration techniques. If no exploration techniques that define a completion
        state are being used, run until there is nothing left to run.

        :param stash:       Operate on this stash
        :param n:           Step at most this many times
        :param until:       If provided, should be a function that takes a SimulationManager and
                            returns True or False. Stepping will terminate when it is True.

        :return:            The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        for _ in itertools.count() if n is None else range(0, n):
            if not self.complete() and self._stashes[stash]:
                self.step(stash=stash, **kwargs)
                if not (until and until(self)):
                    continue
            break
        return self

    def complete(self):
        """
        Returns whether or not this manager has reached a "completed" state.
        """
        if not self._techniques:
            return False
        if not any(tech._is_overriden("complete") for tech in self._techniques):
            return False
        return self.completion_mode(tech.complete(self) for tech in self._techniques if tech._is_overriden("complete"))

    def step(
        self,
        stash="active",
        target_stash=None,
        n=None,
        selector_func=None,
        step_func=None,
        error_list=None,
        successor_func=None,
        until=None,
        filter_func=None,
        **run_args,
    ):
        """
        Step a stash of states forward and categorize the successors appropriately.

        The parameters to this function allow you to control everything about the stepping and
        categorization process.

        :param stash:           The name of the stash to step (default: 'active')
        :param target_stash:    The name of the stash to put the results in (default: same as ``stash``)
        :param error_list:      The list to put ErrorRecord objects in (default: ``self.errored``)
        :param selector_func:   If provided, should be a function that takes a state and returns a
                                boolean. If True, the state will be stepped. Otherwise, it will be
                                kept as-is.
        :param step_func:       If provided, should be a function that takes a SimulationManager and
                                returns a SimulationManager. Will be called with the SimulationManager
                                at every step. Note that this function should not actually perform any
                                stepping - it is meant to be a maintenance function called after each step.
        :param successor_func:  If provided, should be a function that takes a state and return its successors.
                                Otherwise, project.factory.successors will be used.
        :param filter_func:     If provided, should be a function that takes a state and return the name
                                of the stash, to which the state should be moved.
        :param until:           (DEPRECATED) If provided, should be a function that takes a SimulationManager and
                                returns True or False. Stepping will terminate when it is True.
        :param n:               (DEPRECATED) The number of times to step (default: 1 if "until" is not provided)

        Additionally, you can pass in any of the following keyword args for project.factory.successors:

        :param jumpkind:        The jumpkind of the previous exit
        :param addr:            An address to execute at instead of the state's ip.
        :param stmt_whitelist:  A list of stmt indexes to which to confine execution.
        :param last_stmt:       A statement index at which to stop execution.
        :param thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :param backup_state:    A state to read bytes from instead of using project memory.
        :param opt_level:       The VEX optimization level to use.
        :param insn_bytes:      A string of bytes to use for the block instead of the project.
        :param size:            The maximum size of the block, in bytes.
        :param num_inst:        The maximum number of instructions.
        :param traceflags:      traceflags to be passed to VEX. Default: 0

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        l.info("Stepping %s of %s", stash, self)
        # 8<----------------- Compatibility layer -----------------
        if n is not None or until is not None:
            if once("simgr_step_n_until"):
                print(
                    "\x1b[31;1mDeprecation warning: the use of `n` and `until` arguments is deprecated. "
                    "Consider using simgr.run() with the same arguments if you want to specify "
                    "a number of steps or an additional condition on when to stop the execution.\x1b[0m"
                )
            return self.run(
                stash,
                n,
                until,
                selector_func=selector_func,
                step_func=step_func,
                successor_func=successor_func,
                filter_func=filter_func,
                **run_args,
            )
        # ------------------ Compatibility layer ---------------->8
        bucket = defaultdict(list)
        target_stash = target_stash or stash
        error_list = error_list if error_list is not None else self._errored

        for state in self._fetch_states(stash=stash):
            goto = self.filter(state, filter_func=filter_func)
            if isinstance(goto, tuple):
                goto, state = goto

            if goto not in (None, stash):
                bucket[goto].append(state)
                continue

            if not self.selector(state, selector_func=selector_func):
                bucket[stash].append(state)
                continue

            pre_errored = len(error_list)

            successors = self.step_state(state, successor_func=successor_func, error_list=error_list, **run_args)
            # handle degenerate stepping cases here. desired behavior:
            # if a step produced only unsat states, always add them to the unsat stash since this usually indicates bugs
            # if a step produced sat states and save_unsat is False, drop the unsats
            # if a step produced no successors, period, add the original state to deadended

            # first check if anything happened besides unsat. that gates all this behavior
            if not any(v for k, v in successors.items() if k != "unsat") and len(error_list) == pre_errored:
                # then check if there were some unsats
                if successors.get("unsat", []):
                    # only unsats. current setup is acceptable.
                    pass
                else:
                    # no unsats. we've deadended.
                    bucket["deadended"].append(state)
                    continue
            else:
                # there were sat states. it's okay to drop the unsat ones if the user said so.
                if not self._save_unsat:
                    successors.pop("unsat", None)

            for to_stash, successor_states in successors.items():
                bucket[to_stash or target_stash].extend(successor_states)

        self._clear_states(stash=stash)
        for to_stash, states in bucket.items():
            for state in states:
                if self._hierarchy:
                    self._hierarchy.add_state(state)
            self._store_states(to_stash or target_stash, states)

        if step_func is not None:
            return step_func(self)
        return self

    def step_state(self, state, successor_func=None, error_list=None, **run_args):
        """
        Don't use this function manually - it is meant to interface with exploration techniques.
        """
        error_list = error_list if error_list is not None else self._errored
        try:
            successors = self.successors(state, successor_func=successor_func, **run_args)
            stashes = {
                None: successors.flat_successors,
                "unsat": successors.unsat_successors,
                "unconstrained": successors.unconstrained_successors,
            }

        except (SimUnsatError, claripy.UnsatError) as e:
            if LAZY_SOLVES not in state.options:
                error_list.append(ErrorRecord(state, e, sys.exc_info()[2]))
                stashes = {}
            else:
                stashes = {"pruned": [state]}

            if self._hierarchy:
                self._hierarchy.unreachable_state(state)
                self._hierarchy.simplify()

        except claripy.ClaripySolverInterruptError as e:
            resource_event(state, e)
            stashes = {"interrupted": [state]}

        except tuple(self._resilience) as e:
            error_list.append(ErrorRecord(state, e, sys.exc_info()[2]))
            stashes = {}

        return stashes

    def filter(self, state, filter_func=None):  # pylint:disable=no-self-use
        """
        Don't use this function manually - it is meant to interface with exploration techniques.
        """
        if filter_func is not None:
            return filter_func(state)
        return None

    def selector(self, state, selector_func=None):  # pylint:disable=no-self-use
        """
        Don't use this function manually - it is meant to interface with exploration techniques.
        """
        if selector_func is not None:
            return selector_func(state)
        return True

    def successors(self, state, successor_func=None, **run_args):
        """
        Don't use this function manually - it is meant to interface with exploration techniques.
        """
        if successor_func is not None:
            return successor_func(state, **run_args)
        return self._project.factory.successors(state, **run_args)

    #
    #   ...
    #

    def prune(self, filter_func=None, from_stash="active", to_stash="pruned"):
        """
        Prune unsatisfiable states from a stash.

        This function will move all unsatisfiable states in the given stash into a different stash.

        :param filter_func: Only prune states that match this filter.
        :param from_stash:  Prune states from this stash. (default: 'active')
        :param to_stash:    Put pruned states in this stash. (default: 'pruned')

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """

        def _prune_filter(state):
            to_prune = not filter_func or filter_func(state)
            if to_prune and not state.satisfiable():
                if self._hierarchy:
                    self._hierarchy.unreachable_state(state)
                    self._hierarchy.simplify()
                return True
            return False

        self.move(from_stash, to_stash, _prune_filter)
        return self

    def populate(self, stash, states):
        """
        Populate a stash with a collection of states.

        :param stash:   A stash to populate.
        :param states:  A list of states with which to populate the stash.
        """
        self._store_states(stash, states)
        return self

    def absorb(self, simgr):
        """
        Collect all the states from ``simgr`` and put them in their corresponding stashes in this manager.
        This will not modify ``simgr``.
        """
        for stash in simgr.stashes:
            self._store_states(stash, simgr.stashes[stash])
        self._errored.extend(simgr._errored)

    def move(self, from_stash, to_stash, filter_func=None):
        """
        Move states from one stash to another.

        :param from_stash:  Take matching states from this stash.
        :param to_stash:    Put matching states into this stash.
        :param filter_func: Stash states that match this filter. Should be a function that takes
                            a state and returns True or False. (default: stash all states)

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        filter_func = filter_func or (lambda s: True)

        def stash_splitter(states):
            return reversed(self._filter_states(filter_func, states))

        return self.split(stash_splitter, from_stash=from_stash, to_stash=to_stash)

    def stash(self, filter_func=None, from_stash="active", to_stash="stashed"):
        """
        Stash some states. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Stash states that match this filter. Should be a function that
                            takes a state and returns True or False. (default: stash all states)
        :param from_stash:  Take matching states from this stash. (default: 'active')
        :param to_stash:    Put matching states into this stash. (default: 'stashed')

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        return self.move(from_stash, to_stash, filter_func=filter_func)

    def unstash(self, filter_func=None, to_stash="active", from_stash="stashed"):
        """
        Unstash some states. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Unstash states that match this filter. Should be a function that
                            takes a state and returns True or False. (default: unstash all states)
        :param from_stash:  take matching states from this stash. (default: 'stashed')
        :param to_stash:    put matching states into this stash. (default: 'active')

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        return self.move(from_stash, to_stash, filter_func=filter_func)

    def drop(self, filter_func=None, stash="active"):
        """
        Drops states from a stash. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Drop states that match this filter. Should be a function that takes
                            a state and returns True or False. (default: drop all states)
        :param stash:       Drop matching states from this stash. (default: 'active')

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        return self.move(stash, self.DROP, filter_func=filter_func)

    def apply(self, state_func=None, stash_func=None, stash="active", to_stash=None):
        """
        Applies a given function to a given stash.

        :param state_func:  A function to apply to every state. Should take a state and return a state.
                            The returned state will take the place of the old state. If the function
                            *doesn't* return a state, the old state will be used. If the function returns
                            a list of states, they will replace the original states.
        :param stash_func:  A function to apply to the whole stash. Should take a list of states and
                            return a list of states. The resulting list will replace the stash.
                            If both state_func and stash_func are provided state_func is applied first,
                            then stash_func is applied on the results.
        :param stash:       A stash to work with.
        :param to_stash:    If specified, this stash will be used to store the resulting states instead.

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        to_stash = to_stash or stash

        def _stash_splitter(states):
            keep, split = [], []
            if state_func is not None:
                for s in states:
                    ns = state_func(s)
                    if isinstance(ns, SimState):
                        split.append(ns)
                    elif isinstance(ns, (list, tuple, set)):
                        split.extend(ns)
                    else:
                        split.append(s)
            if stash_func is not None:
                split = stash_func(states)
            if to_stash is not stash:
                keep = states
            return keep, split

        return self.split(_stash_splitter, from_stash=stash, to_stash=to_stash)

    def split(
        self,
        stash_splitter=None,
        stash_ranker=None,
        state_ranker=None,
        limit=8,
        from_stash="active",
        to_stash="stashed",
    ):
        """
        Split a stash of states into two stashes depending on the specified options.

        The stash from_stash will be split into two stashes depending on the other options
        passed in. If to_stash is provided, the second stash will be written there.

        stash_splitter overrides stash_ranker, which in turn overrides state_ranker.
        If no functions are provided, the states are simply split according to the limit.

        The sort done with state_ranker is ascending.

        :param stash_splitter:  A function that should take a list of states and return a tuple
                                of two lists (the two resulting stashes).
        :param stash_ranker:    A function that should take a list of states and return a sorted
                                list of states. This list will then be split according to "limit".
        :param state_ranker:    An alternative to stash_splitter. States will be sorted with outputs
                                of this function, which are to be used as a key. The first "limit"
                                of them will be kept, the rest split off.
        :param limit:           For use with state_ranker. The number of states to keep. Default: 8
        :param from_stash:      The stash to split (default: 'active')
        :param to_stash:        The stash to write to (default: 'stashed')

        :returns:               The simulation manager, for chaining.
        :rtype:                 SimulationManager
        """
        states = self._fetch_states(stash=from_stash)

        if stash_splitter is not None:
            keep, split = stash_splitter(states)
        elif stash_ranker is not None:
            ranked_paths = stash_ranker(states)
            keep, split = ranked_paths[:limit], ranked_paths[limit:]
        elif state_ranker is not None:
            ranked_paths = sorted(states, key=state_ranker)
            keep, split = ranked_paths[:limit], ranked_paths[limit:]
        else:
            keep, split = states[:limit], states[limit:]

        keep, split = map(list, (keep, split))

        self._clear_states(from_stash)
        self._store_states(from_stash, keep)
        self._store_states(to_stash, split)
        return self

    @staticmethod
    def _merge_key(state):
        return (
            state.addr if not state.regs._ip.symbolic else "SYMBOLIC",
            [x.func_addr for x in state.callstack],
            set(state.posix.fd) if state.has_plugin("posix") else None,
        )

    def merge(self, merge_func=None, merge_key=None, stash="active", prune=True):
        """
        Merge the states in a given stash.

        :param stash:       The stash (default: 'active')
        :param merge_func:  If provided, instead of using state.merge, call this function with
                            the states as the argument. Should return the merged state.
        :param merge_key:   If provided, should be a function that takes a state and returns a key that will compare
                            equal for all states that are allowed to be merged together, as a first aproximation.
                            By default: uses PC, callstack, and open file descriptors.
        :param prune:       Whether to prune the stash prior to merging it

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        if prune:
            self.prune(from_stash=stash)
        to_merge = self._fetch_states(stash=stash)
        not_to_merge = []
        if merge_key is None:
            merge_key = self._merge_key

        merge_groups = []
        while to_merge:
            base_key = merge_key(to_merge[0])
            g, to_merge = self._filter_states(lambda s: base_key == merge_key(s), to_merge)
            if len(g) <= 1:
                not_to_merge.extend(g)
            else:
                merge_groups.append(g)

        for g in merge_groups:
            try:
                m = self._merge_states(g) if merge_func is None else merge_func(*g)
                not_to_merge.append(m)
            except SimMergeError:
                l.warning("SimMergeError while merging %d states", len(g), exc_info=True)
                not_to_merge.extend(g)

        self._clear_states(stash)
        self._store_states(stash, not_to_merge)
        return self

    #
    #   ...
    #

    def _store_states(self, stash, states):
        if stash not in self._auto_drop:
            with self._lock:
                if stash not in self._stashes:
                    self._stashes[stash] = []
                self._stashes[stash].extend(states)

    def _clear_states(self, stash):
        for _stash in list(self._stashes) if stash == self.ALL else [stash]:
            del self._stashes[_stash][:]

    def _fetch_states(self, stash):
        if stash in self._stashes:
            return self._stashes[stash]
        elif stash == SimulationManager.ALL:
            return list(itertools.chain.from_iterable(self._stashes.values()))
        elif stash == "mp_" + SimulationManager.ALL:
            return mulpyplexer.MP(self._fetch_states(stash=SimulationManager.ALL))
        elif stash.startswith("mp_"):
            return mulpyplexer.MP(self._stashes.get(stash[3:], []))
        elif stash.startswith("one_"):
            return self._stashes.get(stash[4:], [None])[0]
        else:
            raise AttributeError("No such stash: %s" % stash)

    def _filter_states(self, filter_func, states):  # pylint:disable=no-self-use
        match, nomatch = [], []
        for state in states:
            (match if filter_func(state) else nomatch).append(state)
        return match, nomatch

    def _merge_states(self, states):
        """
        Merges a list of states.

        :param states:      the states to merge
        :returns SimState:  the resulting state
        """

        if self._hierarchy:
            optimal, common_history, others = self._hierarchy.most_mergeable(states)
        else:
            optimal, common_history, others = states, None, []

        if len(optimal) >= 2:
            # We found optimal states (states that share a common ancestor) to merge.
            # Compute constraints for each state starting from the common ancestor,
            # and use them as merge conditions.
            constraints = [s.history.constraints_since(common_history) for s in optimal]

            o = optimal[0]
            m, _, _ = o.merge(
                *optimal[1:], merge_conditions=constraints, common_ancestor=common_history.strongref_state
            )

        else:
            l.warning(
                "Cannot find states with common history line to merge. Fall back to the naive merging strategy "
                "and merge all states."
            )
            s = states[0]
            m, _, _ = s.merge(*states[1:])

            others = []

        if self._hierarchy:
            self._hierarchy.add_state(m)

        if len(others):
            others.append(m)
            return self._merge_states(others)
        else:
            return m

    #
    #   ...
    #

    def _create_integral_stashes(self) -> defaultdict[str, list[SimState]]:
        stashes = defaultdict(list)
        stashes.update({name: [] for name in self._integral_stashes})
        return stashes

    def _copy_stashes(self, deep=False):
        stashes = defaultdict(list)

        if not deep:
            # shallow copy
            stashes.update({name: list(stash) for name, stash in self._stashes.items()})
        else:
            # deep copy
            stashes.update({name: [s.copy() for s in stash] for name, stash in self.stashes.items()})
        return stashes

    #
    # Pickling
    #

    def __getstate__(self):
        self.prune()
        s = {k: v for k, v in self.__dict__.items() if not isinstance(v, types.MethodType)}
        if self._hierarchy is not False:
            s["_hierarchy"] = None
        return s

    def __setstate__(self, s):
        self.__dict__.update(s)
        if self._hierarchy is None:
            self._hierarchy = StateHierarchy()

    # 8<----------------- Compatibility layer -----------------
    def _one_step(self, stash, selector_func=None, successor_func=None, **kwargs):
        return self.step(stash=stash, selector_func=selector_func, successor_func=successor_func, **kwargs)

    # ------------------- Compatibility layer --------------->8


class ErrorRecord:
    """
    A container class for a state and an error that was thrown during its execution. You can find these in
    SimulationManager.errored.

    :ivar state:        The state that encountered an error, at the point in time just before the erroring
                        step began.
    :ivar error:        The error that was thrown.
    :ivar traceback:    The traceback for the error that was thrown.
    """

    def __init__(self, state, error, traceback):
        self.state: SimState = state
        self.error: Exception = error
        self.traceback: TracebackType = traceback

    def debug(self):
        """
        Launch a postmortem debug shell at the site of the error.
        """
        try:
            __import__("ipdb").post_mortem(self.traceback)
        except ImportError:
            __import__("pdb").post_mortem(self.traceback)

    def reraise(self):
        raise self.error.with_traceback(self.traceback)

    def __repr__(self):
        return '<State errored with "%s">' % self.error

    def __eq__(self, other):
        return self is other or self.state is other


from .exploration_techniques import ExplorationTechnique, Veritesting, Threading, Explorer, Suggestions
