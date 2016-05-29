import ana
import simuvex
import claripy
import mulpyplexer
import concurrent.futures

import logging
l = logging.getLogger('angr.path_group')



class PathGroup(ana.Storable):
    """
    Path groups are the future.

    Path groups allow you to wrangle multiple paths in a slick way. Paths are organized into "stashes", which you can
    step forward, filter, merge, and move around as you wish. This allows you to, for example, step two different
    stashes of paths at different rates, then merge them together.

    Note that path groups are immutable by default (all operations will return new PathGroup objects). See the immutable
    argument to __init__.

    Stashes can be accessed as attributes (i.e. pg.active). A mulpyplexed stash can be retrieved by prepending the name
    with `mp_` (e.g., `pg.mp_active`).

    Note that you shouldn't usually be constructing path groups directly - there are convenient shortcuts for
    creating path groups in `Project.factory`: see :class:`angr.factory.AngrObjectFactory`.

    Multithreading your search can be useful in z3-intensive paths. Indeed, Python cannot multithread due to its GIL,
    but z3, written in C, can.
    """

    ALL = '_ALL'
    DROP = '_DROP'

    def __init__(self, project, active_paths=None, stashes=None, hierarchy=None, veritesting=None,
                 veritesting_options=None, immutable=None, resilience=None, save_unconstrained=None,
                 save_unsat=None, strong_path_mapping=None, threads=None):
        """
        :param project:         A Project instance.
        :type  project:         angr.project.Project

        The following parameters are optional.

        :param active_paths:    Active paths to seed the "active" stash with.
        :param stashes:         A dictionary to use as the stash store.
        :param hierarchy:       A PathHierarchy object to use to track path reachability.
        :param immutable:       If True, all operations will return a new PathGroup. Otherwise (default), all operations
                                will modify the PathGroup (and return it, for consistency and chaining).
        :param threads:         the number of worker threads to concurrently analyze states (useful in z3-intensive paths).
        """
        self._project = project
        self._hierarchy = PathHierarchy(strong_path_mapping=strong_path_mapping) if hierarchy is None else hierarchy
        self._immutable = False if immutable is None else immutable
        self._veritesting = False if veritesting is None else veritesting
        self._resilience = False if resilience is None else resilience
        self._veritesting_options = { } if veritesting_options is None else veritesting_options

        # public options
        self.save_unconstrained = False if save_unconstrained is None else save_unconstrained
        self.save_unsat = False if save_unsat is None else save_unsat

        # parallelization
        self._threads = threads
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads) if self._threads is not None else None

        self.stashes = {
            'active': [ ] if active_paths is None else active_paths,
            'stashed': [ ],
            'pruned': [ ],
            'unsat': [ ],
            'errored': [ ],
            'deadended': [ ],
            'unconstrained': [ ]
        } if stashes is None else stashes

    #
    # Util functions
    #

    def copy(self, stashes=None):
        stashes = stashes if stashes is not None else self._copy_stashes(immutable=True)
        return PathGroup(self._project, stashes=stashes, hierarchy=self._hierarchy, immutable=self._immutable, veritesting=self._veritesting, veritesting_options=self._veritesting_options, resilience=self._resilience, save_unconstrained=self.save_unconstrained, save_unsat=self.save_unsat)

    def _copy_stashes(self, immutable=None):
        """
        Returns a copy of the stashes (if immutable) or the stashes themselves (if not immutable). Used to abstract away
        immutability.
        """
        if self._immutable if immutable is None else immutable:
            return { k:list(v) for k,v in self.stashes.items() }
        else:
            return self.stashes

    def _copy_paths(self, paths):
        """
        Returns a copy of a list of paths (if immutable) or the paths themselves (if not immutable). Used to abstract
        away immutability.
        """
        if self._immutable:
            return [ p.copy() for p in paths ]
        else:
            return paths

    def _successor(self, new_stashes):
        """
        Creates a new PathGroup with the provided stashes (if immutable), or sets the stashes (if not immutable). Used
        to abstract away immutability.

        :returns:   A PathGroup.
        """
        if '_DROP' in new_stashes:
            del new_stashes['_DROP']

        if not self._immutable:
            self.stashes = new_stashes
            return self
        else:
            return self.copy(stashes=new_stashes)

    def _condition_to_lambda(self, condition, default=False):
        """
        Translates an integer, set or list into a lambda that checks a path address against the given addresses, and the
        other ones from the same basic block

        :param condition:   An integer, set, or list to convert to a lambda.
        :param default:     The default return value of the lambda (in case condition is None). Default: false.

        :returns:           A lambda that takes a path and returns True or False.
        """
        if condition is None:
            condition = lambda p: default

        if isinstance(condition, (int, long)):
            condition = [ condition ]

        if isinstance(condition, (tuple, set, list)):
            addrs = set(condition)
            condition = lambda p: p.addr in addrs or \
                                  addrs.intersection(set(self._project.factory.block(p.addr).instruction_addrs))
        return condition


    @staticmethod
    def _filter_paths(filter_func, paths):
        """
        Filters a sequence of paths according to a filter_func.

        :param filter_func: The filter function. Should take a path as input and return a boolean.
        :param paths:       A sequence of paths.

        :returns:           A tuple, with the first element the matching paths and the second element the non-matching
                            paths.
        """
        l.debug("Filtering %d paths", len(paths))
        match = [ ]
        nomatch = [ ]

        for p in paths:

            if filter_func is not None:
                res = filter_func(p)

                # If result is a one-address-set, we are going to step until
                # the path address is equal to this address (in case the one
                # given to 'find' was not at the beginning of a basic block)
                if isinstance(res, (list, set)):
                    if len(res):
                        elem = res.pop()
                        while p.addr != elem:
                            paths_stepped = p.step(num_inst=1)

                            # We shouldn't go out of the basic block, so there
                            # should only be one path
                            p = paths_stepped[0]
                        res = True
                    else:
                        res = False

            if filter_func is None or res:
                l.debug("... path %s matched!", p)
                match.append(p)
            else:
                l.debug("... path %s didn't match!", p)
                nomatch.append(p)

        l.debug("... returning %d matches and %d non-matches", len(match), len(nomatch))
        return match, nomatch

    def _step_veritesting(self, a):
        veritesting = self._project.analyses.Veritesting(a, **self._veritesting_options)
        if veritesting.result and veritesting.final_path_group:
            pg = veritesting.final_path_group
            pg.stash(from_stash='deviated', to_stash='active')
            pg.stash(from_stash='successful', to_stash='active')

            return pg
        else:
            # return None if veritesting did not work
            return None

    def _one_path_step(self, a, check_func=None, successor_func=None, **kwargs):
        """
        Internal function to step a single path forward.

        :param a:               The path.
        :param check_func:      A function to check the path for an error state.
        :param successor_func:  A function to run on the path instead of doing a.step().

        :returns:               A tuple of lists: successors, unconstrained, unsat, pruned, errored.
        """
        if self._veritesting:
            pg = self._step_veritesting(a)
            if pg is not None:
                return pg.active, pg.stashes.get('unconstrained', []), pg.stashes.get('unsat', []), [], []

        # `check_func` will not be called for Veritesting, this is
        # intended so that we can avoid unnecessarily creating
        # Path._run
        if (check_func is not None and check_func(a)) or (check_func is None and a.errored):
            # This path has error(s)!
            if hasattr(a, "error") and isinstance(a.error, PathUnreachableError):
                return [], [], [], [a], []
            else:
                if self._hierarchy:
                    self._hierarchy.unreachable(a)
                return [], [], [], [], [a]
        else:
            try:
                if successor_func is not None:
                    successors = successor_func(a)
                else:
                    successors = a.step(**kwargs)
                if self._hierarchy:
                    self._hierarchy.add_successors(a, successors)
                return successors, a.unconstrained_successors, a.unsat_successors, [], []
            except (AngrError, simuvex.SimError, claripy.ClaripyError):
                if not self._resilience:
                    raise
                else:
                    l.warning("PathGroup resilience squashed an exception", exc_info=True)
                    return [], [], [], [], [a]

    def _record_step_results(self, new_stashes, new_active, a, successors, unconstrained, unsat, pruned, errored):
        new_active.extend(successors)
        if self.save_unconstrained:
            new_stashes['unconstrained'] += unconstrained
        if self.save_unsat:
            new_stashes['unsat'] += unsat
        new_stashes['pruned'] += pruned
        new_stashes['errored'] += errored

        if a not in pruned and a not in errored and len(successors) == 0:
            new_stashes['deadended'].append(a)

    def _one_step(self, stash=None, selector_func=None, successor_func=None, check_func=None, **kwargs):
        """
        Takes a single step in a given stash.

        :param stash:           The name of the stash (default: 'active').
        :param successor_func:  If provided, this function is called with the path as its only argument. It should
                                return the path's successors. If this is None, path.successors is used, instead.
        :param selector_func:   If provided, should be a lambda that takes a Path and returns a boolean. If True, the
                                path will be stepped. Otherwise, it will be kept as-is.
        :param check_func:      If provided, this function will be called to decide whether the current path is errored
                                or not. Path.errored will not be called anymore.

        :returns:               The successor PathGroup.
        :rtype:                 PathGroup
        """
        stash = 'active' if stash is None else stash

        new_stashes = self._copy_stashes()
        new_active = [ ]
        to_tick = [ ]

        for a in self.stashes[stash]:
            if selector_func is not None and not selector_func(a):
                new_active.append(a)
            else:
                to_tick.append(a)

        if self._executor is None:
            for a in to_tick:
                r = self._one_path_step(a, successor_func=successor_func, check_func=check_func, **kwargs)
                self._record_step_results(new_stashes, new_active, a, *r)
        else:
            tasks = { self._executor.submit(self._one_path_step, a, successor_func=successor_func, check_func=check_func, **kwargs): a for a in to_tick }
            for f in concurrent.futures.as_completed(tasks):
                self._record_step_results(new_stashes, new_active, tasks[f], *f.result())

        new_stashes[stash] = new_active
        return self._successor(new_stashes)

    @staticmethod
    def _move(stashes, filter_func, src, dst):
        """
        Moves all stashes that match the filter_func from src to dst.

        :returns: A new stashes dictionary.
        """
        if dst == PathGroup.ALL:
            raise AngrPathGroupError("Can't handle '_ALL' as a target stash.")
        if src == PathGroup.DROP:
            raise AngrPathGroupError("Can't handle '_DROP' as a source stash.")

        if src == PathGroup.ALL:
            srces = [ a for a in stashes.keys() if a != dst ]
        else:
            srces = [ src ]

        matches = [ ]
        for f in srces:
            to_move, to_keep = PathGroup._filter_paths(filter_func, stashes[f])
            stashes[f] = to_keep
            matches.extend(to_move)

        if dst != PathGroup.DROP:
            if dst not in stashes:
                stashes[dst] = [ ]
            stashes[dst].extend(matches)
        return stashes

    def __repr__(self):
        s = "<PathGroup with "
        s += ', '.join(("%d %s" % (len(v),k)) for k,v in self.stashes.items() if len(v) != 0)
        s += ">"
        return s

    def __getattr__(self, k):
        if k.startswith('mp_'):
            return mulpyplexer.MP(self.stashes[k[3:]])
        else:
            return self.stashes[k]

    def __dir__(self):
        return sorted(set(self.__dict__.keys() +
                          dir(super(PathGroup, self)) +
                          dir(type(self)) +
                          self.stashes.keys() +
                          ['mp_'+k for k in self.stashes.keys()]))

    #
    # Interface
    #

    def apply(self, path_func=None, stash_func=None, stash=None):
        """
        Applies a given function to a given stash.

        :param path_func:   A function to apply to every path. Should take a path and return a path. The returned path
                            will take the place of the old path. If the function *doesn't* return a path, the old
                            path will be used. If the function returns a list of paths, they will replace the original
                            paths.
        :param stash_func:  A function to apply to the whole stash. Should take a list of paths and return a list of
                            paths. The resulting list will replace the stash.

                            If both path_func and stash_func are provided path_func is applied first, then stash_func
                            is applied on the results.

        :returns:           The resulting PathGroup.
        :rtype:             PathGroup
        """
        stash = 'active' if stash is None else stash

        new_stashes = self._copy_stashes()
        new_paths = new_stashes[stash]
        if path_func is not None:
            new_new_paths = [ ]
            for p in new_paths:
                np = path_func(p)
                if isinstance(np, Path):
                    new_new_paths.append(np)
                elif isinstance(np, (list, tuple, set)):
                    new_new_paths.extend(np)
                else:
                    new_new_paths.append(p)
            new_paths = new_new_paths
        if stash_func is not None:
            new_paths = stash_func(new_paths)

        new_stashes[stash] = new_paths
        return self._successor(new_stashes)

    def split(self, stash_splitter=None, stash_ranker=None, path_ranker=None, limit=None, from_stash=None, to_stash=None):
        """
        Split a stash of paths. The stash from_stash will be split into two stashes depending on the other options
        passed in. If to_stash is provided, the second stash will be written there.

        stash_splitter overrides stash_ranker, which in turn overrides path_ranker. If no functions are provided, the
        paths are simply split according to the limit.

        The sort done with path_ranker is ascending.

        :param stash_splitter:  A function that should take a list of paths and return a tuple of two lists (the two
                                resulting stashes).
        :param stash_ranker:    A function that should take a list of paths and return a sorted list of paths. This list
                                will then be split according to "limit".
        :param path_ranker:     An alternative to stash_splitter. Paths will be sorted with outputs of this function.
                                used as a key. The first "limit" of them will be kept, the rest split off.
        :param limit:           For use with path_ranker. The number of paths to keep. Default: 8
        :param from_stash:      The stash to split (default: 'active')
        :param to_stash:        The stash to write to (default: 'stashed')

        :returns:               The resulting PathGroup.
        :rtype:                 PathGroup
        """

        limit = 8 if limit is None else limit
        from_stash = 'active' if from_stash is None else from_stash
        to_stash = 'stashed' if to_stash is None else to_stash

        new_stashes = self._copy_stashes()
        old_paths = new_stashes[from_stash]

        if stash_splitter is not None:
            keep, split = stash_splitter(old_paths)
        elif stash_ranker is not None:
            ranked_paths = stash_ranker(old_paths)
            keep, split = ranked_paths[:limit], ranked_paths[limit:]
        elif path_ranker is not None:
            ranked_paths = sorted(old_paths, key=path_ranker)
            keep, split = ranked_paths[:limit], ranked_paths[limit:]
        else:
            keep, split = old_paths[:limit], old_paths[limit:]

        new_stashes[from_stash] = keep
        new_stashes[to_stash] = split if to_stash not in new_stashes else new_stashes[to_stash] + split
        return self._successor(new_stashes)

    def step(self, n=None, selector_func=None, step_func=None, stash=None,
             successor_func=None, until=None, check_func=None, **kwargs):
        """
        Step a stash of paths forward.

        :param n:               The number of times to step (default: 1 if "until" is not provided)
        :param selector_func:   If provided, should be a lambda that takes a Path and returns a boolean. If True, the
                                path will be stepped. Otherwise, it will be kept as-is.
        :param step_func:       If provided, should be a lambda that takes a PathGroup and returns a PathGroup. Will be
                                called with the PathGroup at every step.
        :param stash:           The name of the stash to step (default: 'active')
        :param successor_func:  If provided, this function will be called with a path to get its successors. Otherwise,
                                path.successors will be used.
        :param until:           If provided, should be a lambda that takes a PathGroup and returns True or False.
                                Stepping will terminate when it is True.
        :param check_func:      If provided, this function will be called to decide whether the current path is errored
                                or not. Path.errored will not be called anymore.

        Additionally, you can pass in any of the following keyword args for project.factory.sim_run:

        :keyword jumpkind:        The jumpkind of the previous exit
        :keyword addr:            An address to execute at instead of the state's ip.
        :keyword stmt_whitelist:  A list of stmt indexes to which to confine execution.
        :keyword last_stmt:       A statement index at which to stop execution.
        :keyword thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :keyword backup_state:    A state to read bytes from instead of using project memory.
        :keyword opt_level:       The VEX optimization level to use.
        :keyword insn_bytes:      A string of bytes to use for the block instead of the project.
        :keyword max_size:        The maximum size of the block, in bytes.
        :keyword num_inst:        The maximum number of instructions.
        :keyword traceflags:      traceflags to be passed to VEX. Default: 0

        :returns:               The resulting PathGroup.
        :rtype:                 PathGroup
        """
        stash = 'active' if stash is None else stash
        n = n if n is not None else 1 if until is None else 100000
        pg = self

        for i in range(n):
            l.debug("Round %d: stepping %s", i, pg)

            pg = pg._one_step(stash=stash, selector_func=selector_func, successor_func=successor_func, check_func=check_func, **kwargs)
            if step_func is not None:
                pg = step_func(pg)

            if len(pg.stashes[stash]) == 0:
                l.debug("Out of paths in stash %s", stash)
                break

            if until is not None and until(pg):
                l.debug("Until function returned true")
                break

        return pg

    def prune(self, filter_func=None, from_stash=None, to_stash=None):
        """
        Prune unsatisfiable paths from a stash.

        :param filter_func: Only prune paths that match this filter.
        :param from_stash:  Prune paths from this stash. (default: 'active')
        :param to_stash:    Put pruned paths in this stash. (default: 'pruned')

        :returns:           The resulting PathGroup.
        :rtype:             PathGroup
        """
        to_stash = 'pruned' if to_stash is None else to_stash
        from_stash = 'active' if from_stash is None else from_stash

        to_prune, new_active = self._filter_paths(filter_func, self.stashes[from_stash])
        new_stashes = self._copy_stashes()

        for p in to_prune:
            if p.errored or not p.state.satisfiable():
                if to_stash not in new_stashes:
                    new_stashes[to_stash] = [ ]
                new_stashes[to_stash].append(p)
                if self._hierarchy:
                    self._hierarchy.unreachable(p)
            else:
                new_active.append(p)

        new_stashes[from_stash] = new_active
        return self._successor(new_stashes)

    def move(self, from_stash, to_stash, filter_func=None):
        """
        Move paths from one stash to another.

        :param from_stash:  Take matching paths from this stash.
        :param to_stash:    Put matching paths into this stash.
        :param filter_func: Stash paths that match this filter. Should be a function that takes a path and returns
                            True or False. Default: stash all paths

        :returns:           The resulting PathGroup.
        :rtype:             PathGroup
        """
        new_stashes = self._copy_stashes()
        self._move(new_stashes, filter_func, from_stash, to_stash)
        return self._successor(new_stashes)

    def stash(self, filter_func=None, from_stash=None, to_stash=None):
        """
        Stash some paths. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Stash paths that match this filter. Should be a function. that takes a path and returns True
                            or False. (default: stash all paths)
        :param from_stash:  Take matching paths from this stash. (default: 'active')
        :param to_stash:    Put matching paths into this stash. (default: 'stashed')

        :returns:           The resulting PathGroup
        :rtype:             PathGroup
        """
        to_stash = 'stashed' if to_stash is None else to_stash
        from_stash = 'active' if from_stash is None else from_stash
        return self.move(from_stash, to_stash, filter_func=filter_func)

    def drop(self, filter_func=None, stash=None):
        """
        Drops paths from a stash. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Drop paths that match this filter. Should be a function that takes a path and returns True
                            or False. (default: drop all paths)
        :param stash:       Drop matching paths from this stash. (default: 'active')

        :returns:           The resulting PathGroup
        :rtype:             PathGroup
        """
        stash = 'active' if stash is None else stash
        return self.move(stash, self.DROP, filter_func=filter_func)

    def unstash(self, filter_func=None, to_stash=None, from_stash=None):
        """
        Unstash some paths. This is an alias for move(), with defaults for the stashes.

        :param filter_func: Unstash paths that match this filter. Should be a function that takes a path and returns
                            True or False. (default: unstash all paths)
        :param from_stash:  take matching paths from this stash. (default: 'stashed')
        :param to_stash:    put matching paths into this stash. (default: 'active')

        :returns:            The resulting PathGroup.
        :rtype:             PathGroup
        """
        to_stash = 'active' if to_stash is None else to_stash
        from_stash = 'stashed' if from_stash is None else from_stash
        return self.move(from_stash, to_stash, filter_func=filter_func)

    def merge(self, merge_func=None, stash=None):
        """
        Merge the states in a given stash.

        :param stash:       The stash (default: 'active')
        :param merge_func:  If provided, instead of using path.merge, call this function with the paths as the argument.
                            Should return the merged path.

        :returns:           The result PathGroup.
        :rtype:             PathGroup
        """
        stash = 'active' if stash is None else stash
        to_merge = self.stashes[stash]
        not_to_merge = [ ]

        merge_groups = [ ]
        while len(to_merge) > 0:
            g, to_merge = self._filter_paths(lambda p: p.addr == to_merge[0].addr, to_merge)
            if len(g) <= 1:
                not_to_merge.extend(g)
            else:
                merge_groups.append(g)

        for g in merge_groups:
            try:
                m = g[0].merge(*g[1:]) if merge_func is None else merge_func(*g)
                not_to_merge.append(m)
            except simuvex.SimMergeError:
                l.warning("SimMergeError while merging %d paths", len(g), exc_info=True)
                not_to_merge.extend(g)

        new_stashes = self._copy_stashes()
        new_stashes[stash] = not_to_merge
        return self._successor(new_stashes)

    #
    # Various canned functionality
    #

    def stash_not_addr(self, addr, from_stash=None, to_stash=None):
        """
        Stash all paths not at address addr from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: p.addr != addr, from_stash=from_stash, to_stash=to_stash)

    def stash_addr(self, addr, from_stash=None, to_stash=None):
        """
        Stash all paths at address addr from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: p.addr == addr, from_stash=from_stash, to_stash=to_stash)

    def stash_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Stash all paths containg address addr in their backtrace from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: addr in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def stash_not_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Stash all paths not containg address addr in their backtrace from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: addr not in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def stash_all(self, from_stash=None, to_stash=None):
        """
        Stash all paths from stash from_stash to stash to_stash.
        """
        return self.stash(lambda p: True, from_stash=from_stash, to_stash=to_stash)

    def unstash_addr(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all paths at address addr.
        """
        return self.unstash(lambda p: p.addr == addr, from_stash=from_stash, to_stash=to_stash)

    def unstash_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all paths containing address addr in their backtrace.
        """
        return self.unstash(lambda p: addr in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def unstash_not_addr(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all paths not at address addr.
        """
        return self.unstash(lambda p: p.addr != addr, from_stash=from_stash, to_stash=to_stash)

    def unstash_not_addr_past(self, addr, from_stash=None, to_stash=None):
        """
        Unstash all paths not containing address addr in their backtrace.
        """
        return self.unstash(lambda p: addr not in p.addr_trace, from_stash=from_stash, to_stash=to_stash)

    def unstash_all(self, from_stash=None, to_stash=None):
        """
        Unstash all paths.
        """
        return self.unstash(lambda p: True, from_stash=from_stash, to_stash=to_stash)

    #
    # High-level functionality
    #

    def explore(self, stash=None, n=None, find=None, avoid=None, num_find=None, found_stash=None, avoid_stash=None, step_func=None):
        """
        A replacement for the Explorer surveyor. Tick stash "stash" forward (up to n times or until num_find paths are
        found), looking for condition "find", avoiding condition "avoid". Stashes found paths into "found_stash' and
        avoided paths into "avoid_stash".

        :param stash:
        :param n:
        :param find:        The addresses we want to reach.
        :param avoid:       The addresses to avoid.
        :param num_find:    Stop when this many paths have been found.
        :param found_stash:
        :param avoid_stash:
        :param step_func    If provided, should be a lambda that takes a PathGroup and returns a PathGroup. Will be
                            called with the PathGroup at every step. TODO: This doesn't work with Veritesting because
                            Veritesting calls step() and we don't pass this function to Veritesting yet.
        :return:            The resulting PathGroup.
        :rtype:             PathGroup
        """
        find = self._condition_to_lambda(find)
        avoid = self._condition_to_lambda(avoid)
        found_stash = 'found' if found_stash is None else found_stash
        avoid_stash = 'avoid' if avoid_stash is None else avoid_stash
        num_find = 1 if num_find is None else num_find
        cur_found = len(self.stashes[found_stash]) if found_stash in self.stashes else 0
        def explore_step_func(pg):
            pg = pg.stash(find, from_stash=stash, to_stash=found_stash) \
              .stash(avoid, from_stash=stash, to_stash=avoid_stash) \
              .prune(from_stash=found_stash)
            if step_func is not None:
                pg = step_func(pg)
            return pg

        until_func = lambda pg: len(pg.stashes[found_stash]) >= cur_found + num_find
        return self.step(n=n, step_func=explore_step_func, until=until_func, stash=stash)

from .path_hierarchy import PathHierarchy
from .errors import PathUnreachableError, AngrError, AngrPathGroupError
from .path import Path
