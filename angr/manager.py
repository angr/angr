import sys
import inspect
import logging
import itertools
from collections import defaultdict

import ana
import claripy
import mulpyplexer

from .errors import SimError, SimMergeError

l = logging.getLogger("angr.manager")


class SimulationManager(ana.Storable):
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

    :param project:         A Project instance.
    :type  project:         angr.project.Project

    The following parameters are optional.

    :param active_states:   Active states to seed the "active" stash with.
    :param stashes:         A dictionary to use as the stash store.
    :param hierarchy:       A StateHierarchy object to use to track the relationships between states.
    :param immutable:       If True, all operations will return a new SimulationManager. Otherwise (default), all operations
                            will modify the SimulationManager (and return it, for consistency and chaining).
    :param threads:         the number of worker threads to concurrently analyze states (useful in z3-intensive situations).

    Multithreading your search can be useful in constraint-solving-intensive situations. Indeed, Python cannot
    multithread due to its GIL, but z3, written in C, can.

    The most important methods you should look at are ``step``, ``explore``, and ``use_technique``.

    :ivar errored:          Not a stash, but a list of ErrorRecords. Whenever a step raises an exception that we catch,
                            the state and some information about the error are placed in this list. You can adjust the
                            list of caught exceptions with the `resilience` parameter.
    :ivar stashes:          All the stashes on this instance, as a dictionary.
    :ivar completion_mode:  A function describing how multiple exploration techniques with the ``complete`` hook set will
                            interact. By default, the builtin function ``any``.
    """

    ALL = '_ALL'
    DROP = '_DROP'

    def __init__(self, project, active_states=None, stashes=None, hierarchy=None, veritesting=None,
                 veritesting_options=None, immutable=None, resilience=None, save_unconstrained=None,
                 save_unsat=None, threads=None, errored=None, completion_mode=any):
        self._project = project
        self._hierarchy = StateHierarchy() if hierarchy is None else hierarchy
        self._immutable = False if immutable is None else immutable
        self._resilience = False if resilience is None else resilience

        # public options
        self.save_unconstrained = False if save_unconstrained is None else save_unconstrained
        self.save_unsat = False if save_unsat is None else save_unsat

        # techniques
        self._hooks_step = []
        self._hooks_step_state = []
        self._hooks_filter = []
        self._hooks_complete = []
        self._hooks_all = []

        if threads is not None:
            self.use_technique(exploration_techniques.Threading(threads))
        if veritesting:
            self.use_technique(exploration_techniques.Veritesting(
                **({} if veritesting_options is None else veritesting_options)
            ))

        self.errored = [] if errored is None else list(errored)
        self.stashes = self._make_stashes_dict(active=active_states) if stashes is None else stashes
        self.completion_mode = completion_mode

    #
    # Pickling
    #

    def _ana_getstate(self):
        self.prune()
        s = dict(self.__dict__)
        if self._hierarchy is not False:
            s['_hierarchy'] = None
        del s['_hooks_step']
        del s['_hooks_step_state']
        del s['_hooks_filter']
        del s['_hooks_complete']
        return s

    def _ana_setstate(self, s):
        hooks = s.pop('_hooks_all')
        self.__dict__.update(s)
        if self._hierarchy is None:
            self._hierarchy = StateHierarchy()
        self._hooks_step = []
        self._hooks_step_state = []
        self._hooks_filter = []
        self._hooks_complete = []
        self._hooks_all = []
        for hook in hooks:
            self._apply_hooks(hook)

    #
    # Util functions
    #

    def copy(self, stashes=None):
        stashes = stashes if stashes is not None else self._copy_stashes(immutable=True)
        out = SimulationManager(self._project, stashes=stashes, hierarchy=self._hierarchy, immutable=self._immutable, resilience=self._resilience, save_unconstrained=self.save_unconstrained, save_unsat=self.save_unsat, errored=self.errored)
        out._hooks_all = list(self._hooks_all)
        out._hooks_step = list(self._hooks_step)
        out._hooks_step_state = list(self._hooks_step_state)
        out._hooks_filter = list(self._hooks_filter)
        out._hooks_complete = list(self._hooks_complete)
        out.completion_mode = self.completion_mode
        return out

    def _make_stashes_dict(self,
        active=None, unconstrained=None, unsat=None, pruned=None, deadended=None, orig=None, **kwargs
    ):
        for key in kwargs:
            if key not in self.stashes and hasattr(self, key):
                raise SimulationManagerError("'%s' is an illegal stash name - already in use as attribute" % key)

        always_present = {'active': active or [],
                          'unconstrained': unconstrained or [],
                          'unsat': unsat or [],
                          'pruned': pruned or [],
                          'deadended': deadended or []
                          }
        if not active and not unconstrained and orig:
            always_present['deadended'].append(orig)

        result = defaultdict(list, always_present, **kwargs)
        return result

    def _copy_stashes(self, immutable=None):
        """
        Returns a copy of the stashes (if immutable) or the stashes themselves (if not immutable). Used to abstract away
        immutability.
        """
        if self._immutable if immutable is None else immutable:
            result = self._make_stashes_dict(**{k: list(v) for k, v in self.stashes.items()})
        else:
            result = defaultdict(list, self.stashes)

        return result

    def _copy_states(self, states):
        """
        Returns a copy of a list of states (if immutable) or the states themselves (if not immutable). Used to abstract
        away immutability.
        """
        if self._immutable:
            return [ p.copy() for p in states ]
        else:
            return states

    def _successor(self, new_stashes):
        """
        Creates a new SimulationManager with the provided stashes (if immutable), or sets the stashes (if not immutable). Used
        to abstract away immutability.

        :returns:   A SimulationManager.
        """
        if self.DROP in new_stashes:
            del new_stashes[self.DROP]

        if not self._immutable:
            self.stashes = new_stashes
            return self
        else:
            return self.copy(stashes=new_stashes)


    @staticmethod
    def _filter_states(filter_func, states):
        """
        Filters a sequence of states according to a filter_func.

        :param filter_func: The filter function. Should take a state as input and return a boolean.
        :param states:      A sequence of states.

        :returns:           A tuple, with the first element the matching states and the second element the non-matching
                            states.
        """
        if filter_func is None:
            return states, []       # does this condition actually matter

        l.debug("Filtering %d states", len(states))
        match = [ ]
        nomatch = [ ]

        for p in states:
            if filter_func(p):
                l.debug("... state %s matched!", p)
                match.append(p)
            else:
                l.debug("... state %s didn't match!", p)
                nomatch.append(p)

        l.debug("... returning %d matches and %d non-matches", len(match), len(nomatch))
        return match, nomatch

    def _one_state_step(self, a, successor_func=None, resilience=None, **kwargs):
        """
        Internal function to step a single state forward.

        :param a:               The state.
        :param successor_func:  A function to run on the state instead of doing a.step().
        :param resilience:      Quash all errors (and put the offending state in the errored stash).

        :returns:               A dict mapping stash names to state lists
        """

        # this is our baby. we fill it with our results.
        new_stashes = {}

        # we keep a strong reference here since the hierarchy handles trimming it
        if self._hierarchy:
            kwargs["strong_reference"] = True

        # wrap any call we make out to user code in this try-except for resilliance
        try:
            # if we have a hook, use it. If we succeed at using the hook, we will break out of this loop
            # otherwise we execute the else-clause, which does the normal step procedure
            for hook in self._hooks_step_state:
                # FIXME hack to handle some hooks not expecting strong_reference
                argspec = inspect.getargspec(hook)
                if argspec.keywords is None and "strong_reference" not in argspec.args:
                    del kwargs["strong_reference"]

                out = hook(a, **kwargs)
                if out is not None:
                    if isinstance(out, tuple):
                        l.warning('step_state returning a tuple has been deprecated! Please return a dict of stashes instead.')
                        a, unconst, unsat, p, e = out
                        out = {'active': a, 'unconstrained': unconst, 'unsat': unsat, 'pruned': p}

                    # errored is not anymore a stash
                    if 'errored' in out:
                        self.errored += out['errored']
                        del out['errored']

                    new_stashes = self._make_stashes_dict(**out)
                    break
            else:
                if successor_func is not None:
                    ss = successor_func(a)
                else:
                    ss = self._project.factory.successors(a, **kwargs)

                new_stashes = self._make_stashes_dict(
                    active=ss.flat_successors,
                    unconstrained=ss.unconstrained_successors,
                    unsat=ss.unsat_successors,
                    orig=a
                )
        except (SimUnsatError, claripy.UnsatError) as e:
            new_stashes = self._make_stashes_dict(pruned=[a])
            if self._hierarchy:
                self._hierarchy.unreachable_state(a)
                self._hierarchy.simplify()
        except (AngrError, SimError, claripy.ClaripyError) as e:
            self.errored.append(ErrorRecord(a, e, sys.exc_info()[2]))
        except (KeyError, IndexError, TypeError, ValueError, ArithmeticError, MemoryError) as e:
            if resilience is False or not self._resilience:
                raise
            self.errored.append(ErrorRecord(a, e, sys.exc_info()[2]))

        return new_stashes

    def _record_step_results(self, new_stashes, new_active, successor_stashes):
        """
        Take a whole bunch of intermediate values and smushes them together

        :param new_stashes:         The dict of stashes that will be modified by this operation
        :param new_active:          One of the lists in new_stashes that is being actively ticked
        :param a:                   The state that just got ticked
        :param successor_stashes:   A dict of the stashs and their states that were created by stepping the state a.
        """

        if self._hierarchy:
            for s in successor_stashes.get('active', []):
                self._hierarchy.add_state(s)
            self._hierarchy.simplify()

        if len(self._hooks_filter) == 0:
            new_active.extend(successor_stashes.get('active', []))
        else:
            for state in successor_stashes.get('active', []):
                self._apply_filter_hooks(state,new_stashes,new_active)

        if self.save_unconstrained:
            new_stashes['unconstrained'] += successor_stashes.get('unconstrained', [])
        if self.save_unsat:
            new_stashes['unsat'] += successor_stashes.get('unsat', [])

        for key in successor_stashes:
            if key not in ('unconstrained', 'unsat', 'active'):
                new_stashes[key].extend(successor_stashes[key])

    def _apply_filter_hooks(self,state,new_stashes,new_active):

        for hook in self._hooks_filter:
            goto = hook(state)
            if goto is None:
                continue
            if type(goto) is tuple:
                goto, state = goto

            if goto in new_stashes:
                new_stashes[goto].append(state)
                break
            else:
                new_stashes[goto] = [state]
                break
        else:
            new_active.append(state)

        return new_active

    def _one_step(self, stash, selector_func=None, successor_func=None, **kwargs):
        """
        Takes a single step in a given stash.

        :param stash:           The name of the stash.
        :param successor_func:  If provided, this function is called with the state as its only argument. It should
                                return the state's successors. If this is None, state.successors is used, instead.
        :param selector_func:   If provided, should be a lambda that takes a state and returns a boolean. If True, the
                                state will be stepped. Otherwise, it will be kept as-is.

        :returns:               The successor SimulationManager.
        :rtype:                 SimulationManager
        """
        # hooking step is a bit of an ordeal, how are you supposed to compose stepping operations?
        # the answer is that you nest them - any stepping hook must eventually call step itself,
        # at which point it calls the next hook, and so on, until we fall through to the
        # basic stepping operation.
        if len(self._hooks_step) != 0:
            hook = self._hooks_step.pop()
            pg = self.copy() if self._immutable else self
            pg._immutable = False       # this is a performance consideration
            out = hook(pg, stash, selector_func=selector_func, successor_func=successor_func, **kwargs)
            out._immutable = self._immutable
            self._hooks_step.append(hook)
            if out is not self:
                out._hooks_step.append(hook)
            return out

        # this is going to be the new stashes dictionary when we're done.
        # We will construct it incrementally.
        new_stashes = self._copy_stashes()

        # Pick which states to tick, putting them in the new_active list
        new_active = []
        if selector_func is None:
            to_tick = list(self.stashes[stash])
        else:
            to_tick = []
            for a in self.stashes[stash]:
                if selector_func(a):
                    to_tick.append(a)
                else:
                    new_active.append(a)

        # wipe out the stash we're drawing from. we will replenish it.
        new_stashes[stash] = []

        # for each state we want to tick, tick it!
        # each tick produces a dict of stashes. use _record_step_results to dump them into the result pool.
        for a in to_tick:
            result_stashes = self._one_state_step(a, successor_func=successor_func, **kwargs)
            self._record_step_results(new_stashes, new_active, result_stashes)

        # finish up and return our result! this may just be the same as self because of mutability optimizations
        new_stashes[stash].extend(new_active)
        return self._successor(new_stashes)

    @staticmethod
    def _move(stashes, filter_func, src, dst):
        """
        Moves all stashes that match the filter_func from src to dst.

        :returns: A new stashes dictionary.
        """
        if dst == SimulationManager.ALL:
            raise SimulationManagerError("Can't handle '_ALL' as a target stash.")
        if src == SimulationManager.DROP:
            raise SimulationManagerError("Can't handle '_DROP' as a source stash.")

        if src == SimulationManager.ALL:
            srces = [ a for a in stashes.keys() if a != dst ]
        else:
            srces = [ src ]

        matches = [ ]
        for f in srces:
            to_move, to_keep = SimulationManager._filter_states(filter_func, stashes[f])
            stashes[f] = to_keep
            matches.extend(to_move)

        if dst != SimulationManager.DROP:
            if dst not in stashes:
                stashes[dst] = [ ]
            stashes[dst].extend(matches)
        return stashes

    def __repr__(self):
        state_list = ', '.join(("%d %s" % (len(v),k)) for k,v in self.stashes.items() if len(v) != 0)
        if state_list == '':
            state_list = '(empty)'
        else:
            state_list = 'with ' + state_list

        errored_part = ' (%d errored)' % len(self.errored) if self.errored else ''

        return "<SimulationManager %s%s>" % (state_list, errored_part)

    def mulpyplex(self, *stashes):
        """
        Mulpyplex across several stashes.

        :param stashes: the stashes to mulpyplex
        :return: a mulpyplexed list of states from the stashes in question, in the specified order
        """

        return mulpyplexer.MP(list(itertools.chain.from_iterable(self.stashes[s] for s in stashes)))

    def __getattr__(self, k):
        if k == SimulationManager.ALL:
            return [ p for p in itertools.chain.from_iterable(s for s in self.stashes.values()) ]
        elif k == 'mp_' + SimulationManager.ALL:
            return mulpyplexer.MP([ p for p in itertools.chain.from_iterable(s for s in self.stashes.values()) ])
        elif k.startswith('mp_'):
            return mulpyplexer.MP(self.stashes[k[3:]])
        elif k.startswith('one_') and k[4:] in self.stashes:
            return self.stashes[k[4:]][0]
        elif k in self.stashes:
            return self.stashes[k]
        else:
            raise AttributeError(k)

    def __dir__(self):
        return sorted(set(
            self.__dict__.keys() +
            dir(super(SimulationManager, self)) +
            dir(type(self)) +
            self.stashes.keys() +
            ['mp_'+k for k in self.stashes.keys()] +
            ['one_'+k for k in self.stashes.keys()]
        ))

    #
    # Interface
    #

    def apply(self, state_func=None, stash_func=None, stash=None):
        """
        Applies a given function to a given stash.

        :param state_func:  A function to apply to every state. Should take a state and return a state. The returned state
                            will take the place of the old state. If the function *doesn't* return a state, the old
                            state will be used. If the function returns a list of states, they will replace the original
                            states.
        :param stash_func:  A function to apply to the whole stash. Should take a list of states and return a list of
                            states. The resulting list will replace the stash.

                            If both state_func and stash_func are provided state_func is applied first, then stash_func
                            is applied on the results.

        :returns:           The resulting SimulationManager.
        :rtype:             SimulationManager
        """
        stash = 'active' if stash is None else stash

        new_stashes = self._copy_stashes()
        new_states = new_stashes[stash]
        if state_func is not None:
            new_new_states = [ ]
            for p in new_states:
                np = state_func(p)
                if isinstance(np, SimState):
                    new_new_states.append(np)
                elif isinstance(np, (list, tuple, set)):
                    new_new_states.extend(np)
                else:
                    new_new_states.append(p)
            new_states = new_new_states
        if stash_func is not None:
            new_states = stash_func(new_states)

        new_stashes[stash] = new_states
        return self._successor(new_stashes)

    def split(self, stash_splitter=None, stash_ranker=None, state_ranker=None, limit=None, from_stash=None, to_stash=None):
        """
        Split a stash of states. The stash from_stash will be split into two stashes depending on the other options
        passed in. If to_stash is provided, the second stash will be written there.

        stash_splitter overrides stash_ranker, which in turn overrides state_ranker. If no functions are provided, the
        states are simply split according to the limit.

        The sort done with state_ranker is ascending.

        :param stash_splitter:  A function that should take a list of states and return a tuple of two lists (the two
                                resulting stashes).
        :param stash_ranker:    A function that should take a list of states and return a sorted list of states. This list
                                will then be split according to "limit".
        :param state_ranker:        An alternative to stash_splitter. States will be sorted with outputs of this function.
                                used as a key. The first "limit" of them will be kept, the rest split off.
        :param limit:           For use with state_ranker. The number of states to keep. Default: 8
        :param from_stash:      The stash to split (default: 'active')
        :param to_stash:        The stash to write to (default: 'stashed')

        :returns:               The resulting SimulationManager.
        :rtype:                 SimulationManager
        """

        limit = 8 if limit is None else limit
        from_stash = 'active' if from_stash is None else from_stash
        to_stash = 'stashed' if to_stash is None else to_stash

        new_stashes = self._copy_stashes()
        old_states = new_stashes[from_stash]

        if stash_splitter is not None:
            keep, split = stash_splitter(old_states)
        elif stash_ranker is not None:
            ranked_states = stash_ranker(old_states)
            keep, split = ranked_states[:limit], ranked_states[limit:]
        elif state_ranker is not None:
            ranked_states = sorted(old_states, key=state_ranker)
            keep, split = ranked_states[:limit], ranked_states[limit:]
        else:
            keep, split = old_states[:limit], old_states[limit:]

        new_stashes[from_stash] = keep
        new_stashes[to_stash] = split if to_stash not in new_stashes else new_stashes[to_stash] + split
        return self._successor(new_stashes)

    def step(self, n=None, selector_func=None, step_func=None, stash=None,
             successor_func=None, until=None, **kwargs):
        """
        Step a stash of states forward and categorize the successors appropriately.

        The parameters to this function allow you to control everything about the stepping and categorization process.

        :param stash:           The name of the stash to step (default: 'active')
        :param n:               The number of times to step (default: 1 if "until" is not provided)
        :param selector_func:   If provided, should be a function that takes a state and returns a boolean. If True, the
                                state will be stepped. Otherwise, it will be kept as-is.
        :param step_func:       If provided, should be a function that takes a SimulationManager and returns a SimulationManager. Will
                                be called with the SimulationManager at every step. Note that this function should not actually
                                perform any stepping - it is meant to be a maintenance function called after each step.
        :param successor_func:  If provided, should be a function that takes a state and return its successors.
                                Otherwise, project.factory.successors will be used.
        :param until:           If provided, should be a function that takes a SimulationManager and returns True or False.
                                Stepping will terminate when it is True.

        Additionally, you can pass in any of the following keyword args for project.factory.sim_run:

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

        The following parameters are specific to the unicorn-engine.

        :param extra_stop_points: A collection of addresses where unicorn should stop, in addition to default program
                                  points at which unicorn stops (e.g., hook points).

        :returns:               The resulting SimulationManager.
        :rtype:                 SimulationManager
        """
        stash = 'active' if stash is None else stash
        if until is None and n is None:
            n = 1
        pg = self

        # Check for found state in first block
        new_active = []
        for state in pg.stashes[stash]:
            self._apply_filter_hooks(state,pg.stashes,new_active)
        pg.stashes[stash] = new_active

        i = 0
        while n is None or i < n:
            i += 1
            l.debug("Round %d: stepping %s", i, pg)

            pg = pg._one_step(stash=stash, selector_func=selector_func, successor_func=successor_func, **kwargs)
            if step_func is not None:
                pg = step_func(pg)

            if until is not None and until(pg):
                l.debug("Until function returned true")
                break

            if len(pg.stashes[stash]) == 0:
                l.debug("Out of states in stash %s", stash)
                break


        return pg

    def prune(self, filter_func=None, from_stash=None, to_stash=None):
        """
        Prune unsatisfiable states from a stash.
        This function will move all unsatisfiable states in the given stash into a different stash.

        :param filter_func: Only prune states that match this filter.
        :param from_stash:  Prune states from this stash. (default: 'active')
        :param to_stash:    Put pruned states in this stash. (default: 'pruned')

        :returns:           The resulting SimulationManager.
        :rtype:             SimulationManager
        """
        to_stash = 'pruned' if to_stash is None else to_stash
        from_stash = 'active' if from_stash is None else from_stash

        to_prune, new_active = self._filter_states(filter_func, self.stashes[from_stash])
        new_stashes = self._copy_stashes()

        for s in to_prune:
            if not s.satisfiable():
                if to_stash not in new_stashes:
                    new_stashes[to_stash] = [ ]
                new_stashes[to_stash].append(s)
                if self._hierarchy:
                    self._hierarchy.unreachable_state(s)
                    self._hierarchy.simplify()
            else:
                new_active.append(s)

        new_stashes[from_stash] = new_active
        return self._successor(new_stashes)

    def move(self, from_stash, to_stash, filter_func=None):
        """
        Move states from one stash to another.

        :param from_stash:  Take matching states from this stash.
        :param to_stash:    Put matching states into this stash.
        :param filter_func: Stash states that match this filter. Should be a function that takes a state and returns
                            True or False. Default: stash all states

        :returns:           The resulting SimulationManager.
        :rtype:             SimulationManager
        """
        new_stashes = self._copy_stashes()
        self._move(new_stashes, filter_func, from_stash, to_stash)
        return self._successor(new_stashes)

    def stash(self, filter_func=None, from_stash=None, to_stash=None):
        """
        Stash some states. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Stash states that match this filter. Should be a function. that takes a state and returns True
                            or False. (default: stash all states)
        :param from_stash:  Take matching states from this stash. (default: 'active')
        :param to_stash:    Put matching states into this stash. (default: 'stashed')

        :returns:           The resulting SimulationManager
        :rtype:             SimulationManager
        """
        to_stash = 'stashed' if to_stash is None else to_stash
        from_stash = 'active' if from_stash is None else from_stash
        return self.move(from_stash, to_stash, filter_func=filter_func)

    def drop(self, filter_func=None, stash=None):
        """
        Drops states from a stash. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Drop states that match this filter. Should be a function that takes a state and returns True
                            or False. (default: drop all states)
        :param stash:       Drop matching states from this stash. (default: 'active')

        :returns:           The resulting SimulationManager
        :rtype:             SimulationManager
        """
        stash = 'active' if stash is None else stash
        return self.move(stash, self.DROP, filter_func=filter_func)

    def unstash(self, filter_func=None, to_stash=None, from_stash=None):
        """
        Unstash some states. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Unstash states that match this filter. Should be a function that takes a state and returns
                            True or False. (default: unstash all states)
        :param from_stash:  take matching states from this stash. (default: 'stashed')
        :param to_stash:    put matching states into this stash. (default: 'active')

        :returns:            The resulting SimulationManager.
        :rtype:             SimulationManager
        """
        to_stash = 'active' if to_stash is None else to_stash
        from_stash = 'stashed' if from_stash is None else from_stash
        return self.move(from_stash, to_stash, filter_func=filter_func)

    def _merge_states(self, states):
        """
        Merges a list of states.

        :param states: the states to merge
        :returns: the resulting state
        :rtype: SimState
        """

        if self._hierarchy:
            optimal, common_history, others = self._hierarchy.most_mergeable(states)
        else:
            optimal, common_history, others = states, None, [ ]

        if len(optimal) >= 2:
            # We found optimal states (states that share a common ancestor) to merge

            # compute constraints for each state starting from the common ancestor, and use them as merge conditions
            constraints = [ s.history.constraints_since(common_history) for s in optimal ]

            o = optimal[0]
            m, _, _ = o.merge(*optimal[1:],
                              merge_conditions=constraints,
                              # history.strongref_state requires state option EFFICIENT_STATE_MERGING
                              common_ancestor=common_history.strongref_state,
                              common_ancestor_history=common_history
                              )

        else:
            l.warning("Cannot find states with common history line to merge. Fall back to the naive merging strategy"
                      "and merge all states."
                      )
            s = states[0]
            m, _, _ = s.merge(*states[1:])

            others = [ ]

        if self._hierarchy:
            self._hierarchy.add_state(m)

        if len(others):
            others.append(m)
            return self._merge_states(others)
        else:
            return m

    def merge(self, merge_func=None, stash=None):
        """
        Merge the states in a given stash.

        :param stash:       The stash (default: 'active')
        :param merge_func:  If provided, instead of using state.merge, call this function with the states as the argument.
                            Should return the merged state.

        :returns:           The result SimulationManager.
        :rtype:             SimulationManager
        """
        stash = 'active' if stash is None else stash
        self.prune(from_stash=stash)
        to_merge = self.stashes[stash]
        not_to_merge = [ ]

        merge_groups = [ ]
        while len(to_merge) > 0:
            g, to_merge = self._filter_states(lambda s: s.addr == to_merge[0].addr, to_merge)
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

        new_stashes = self._copy_stashes()
        new_stashes[stash] = not_to_merge
        return self._successor(new_stashes)

    def use_technique(self, tech):
        """
        Use an exploration technique with this SimulationManager.
        Techniques can be found in :mod:`angr.exploration_techniques`.

        :param tech:    An ExplorationTechnique object that contains code to modify this SimulationManager's behavior
        :returns:       The same technique instance that was passed in. This allows for writing the
                        ExplorationTechnique construtor call inside the call to ``use_technique`` and still
                        maintaining a reference to the technique.
        """
        # this might be the best worst code I've ever written in my life
        tech.project = self._project
        self.remove_tech(tech)
        tech.setup(self)
        self._apply_hooks(tech)
        return tech

    def _apply_hooks(self, tech):
        self._hooks_all.append(tech)
        for hook in ['step_state', 'step', 'filter', 'complete']:
            hookfunc = getattr(tech, hook)
            if hookfunc.im_func is not getattr(exploration_techniques.ExplorationTechnique, hook).im_func:
                getattr(self, '_hooks_' + hook).append(hookfunc)

    def remove_tech(self, tech):
        try:
            self._hooks_all.remove(tech)
        except ValueError:
            return

        for hook in ['step_state', 'step', 'filter', 'complete']:
            try:
                getattr(self, '_hooks_' + hook).remove(getattr(tech, hook))
            except ValueError:
                pass        # it'll error if it wasn't hooked but we don't care

    #
    # Various canned functionality
    #

    def stash_not_addr(self, addr, from_stash=None, to_stash=None):
        """
        Stash all states not at address addr from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: p.addr != addr, from_stash=from_stash, to_stash=to_stash)

    def stash_addr(self, addr, from_stash=None, to_stash=None):
        """
        Stash all states at address addr from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: p.addr == addr, from_stash=from_stash, to_stash=to_stash)

    def stash_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Stash all states containg address addr in their backtrace from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: addr in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def stash_not_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Stash all states not containg address addr in their backtrace from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: addr not in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def stash_all(self, from_stash=None, to_stash=None):
        """
        Stash all states from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: True, from_stash=from_stash, to_stash=to_stash)

    def unstash_addr(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all states at address addr.
        """
        return self.unstash(lambda p: p.addr == addr, from_stash=from_stash, to_stash=to_stash)

    def unstash_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all states containing address addr in their backtrace.
        """
        return self.unstash(lambda p: addr in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def unstash_not_addr(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all states not at address addr.
        """
        return self.unstash(lambda p: p.addr != addr, from_stash=from_stash, to_stash=to_stash)

    def unstash_not_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all states not containing address addr in their backtrace.
        """
        return self.unstash(lambda p: addr not in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def unstash_all(self, from_stash=None, to_stash=None):
        """
        Unstash all states.
        """
        return self.unstash(lambda p: True, from_stash=from_stash, to_stash=to_stash)

    #
    # High-level functionality
    #

    def explore(self, stash=None, n=None, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None, num_find=1, step_func=None, **kwargs):
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
        num_find += len(self.stashes[find_stash]) if find_stash in self.stashes else 0
        tech = exploration_techniques.Explorer(find=find,
                                   avoid=avoid,
                                   find_stash=find_stash,
                                   avoid_stash=avoid_stash,
                                   cfg=cfg,
                                   num_find=num_find)
        self.use_technique(tech)
        out = self.run(stash=stash,
                       step_func=step_func,
                       n=n,
                       **kwargs)
        out.remove_tech(tech)
        self.remove_tech(tech)
        return out

    def run(self, stash=None, n=None, step_func=None, **kwargs):
        """
        Run until the SimulationManager has reached a completed state, according to
        the current exploration techniques.

        TODO: step_func doesn't work with veritesting, since veritesting replaces
        the default step logic.

        :param stash:       Operate on this stash
        :param n:           Step at most this many times
        :param step_func:   If provided, should be a function that takes a SimulationManager and returns a new SimulationManager. Will
                            be called with the current SimulationManager at every step.
        :return:            The resulting SimulationManager.
        :rtype:             SimulationManager
        """
        if len(self._hooks_complete) == 0 and n is None:
            l.warn("No completion state defined for SimulationManager; stepping until all states deadend")

        until_func = lambda pg: self.completion_mode(h(pg) for h in self._hooks_complete)
        return self.step(n=n, step_func=step_func, until=until_func, stash=stash, **kwargs)


class ErrorRecord(object):
    """
    A container class for a state and an error that was thrown during its execution. You can find these in
    SimulationManager.errored.

    :ivar state:        The state that encountered an error, at the point in time just before the erroring step began
    :ivar error:        The error that was thrown
    :ivar traceback:    The traceback for the error that was thrown
    """
    def __init__(self, state, error, traceback):
        self.state = state
        self.error = error
        self.traceback = traceback

    def debug(self):
        """
        Launch a postmortem debug shell at the site of the error
        """
        try:
            __import__('ipdb').post_mortem(self.traceback)
        except ImportError:
            __import__('pdb').post_mortem(self.traceback)

    def __repr__(self):
        return '<State errored with "%s">' % self.error

    def __eq__(self, other):
        return self is other or self.state is other

from .sim_state import SimState
from .state_hierarchy import StateHierarchy
from .errors import AngrError, SimUnsatError, SimulationManagerError
from . import exploration_techniques
