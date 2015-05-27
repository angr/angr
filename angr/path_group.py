import ana
import simuvex
import mulpyplexer

import logging
l = logging.getLogger('angr.path_group')

class PathGroup(ana.Storable):
    def __init__(self, project, active_paths=None, stashes=None, hierarchy=None, immutable=True):
        self._project = project
        self._hierarchy = PathHierarchy() if hierarchy is None else hierarchy
        self._immutable = immutable

        self.stashes = {
            'active': [ ] if active_paths is None else active_paths,
            'stashed': [ ],
            'pruned': [ ],
            'errored': [ ],
            'deadended': [ ]
        } if stashes is None else stashes

    #
    # Util functions
    #

    def _copy_stashes(self):
        if self._immutable:
            return { k:list(v) for k,v in self.stashes.items() }
        else:
            return self.stashes

    def _successor(self, new_stashes):
        if not self._immutable:
            self.stashes = new_stashes
            return self
        else:
            return PathGroup(self._project, stashes=new_stashes, hierarchy=self._hierarchy, immutable=self._immutable)

    @staticmethod
    def _condition_to_lambda(condition, default=False):
        if condition is None:
            condition = lambda p: default

        if isinstance(condition, (int, long)):
            condition = { condition }

        if isinstance(condition, (tuple, set, list)):
            addrs = set(condition)
            condition = lambda p: p.addr in addrs

        return condition

    @staticmethod
    def _filter_paths(filter_func, paths):
        l.debug("Filtering %d paths", len(paths))
        match = [ ]
        nomatch = [ ]

        for p in paths:
            if filter_func(p):
                l.debug("... path %s matched!", p)
                match.append(p)
            else:
                l.debug("... path %s didn't match!", p)
                nomatch.append(p)

        l.debug("... returning %d matches and %d non-matches", len(match), len(nomatch))
        return match, nomatch

    def _one_step(self, stash=None, successor_func=None):
        stash = 'active' if stash is None else stash

        new_stashes = self._copy_stashes()
        new_active = [ ]

        for a in self.stashes[stash]:
            if a.errored:
                if isinstance(a.error, PathUnreachableError):
                    new_stashes['pruned'].append(a)
                else:
                    self._hierarchy.unreachable(a)
                    new_stashes['errored'].append(a)
            else:
                successors = a.successors if successor_func is None else successor_func(a)

                if len(successors) == 0:
                    new_stashes['deadended'].append(a)
                else:
                    new_active.extend(successors)

        new_stashes[stash] = new_active
        return self._successor(new_stashes)

    @staticmethod
    def _move(stashes, filter_func, from_stash, to_stash):
        to_move, to_keep = PathGroup._filter_paths(filter_func, stashes[from_stash])
        if to_stash not in stashes:
            stashes[to_stash] = [ ]

        stashes[to_stash].extend(to_move)
        stashes[from_stash] = to_keep
        return stashes

    def __repr__(self):
        s = "<PathGroup with "
        s += ', '.join(("%d %s" % (len(v),k)) for k,v in self.stashes.items())
        s += ">"
        return s

    def __getattr__(self, k):
        if k.startswith('mp_'):
            return mulpyplexer.MP(self.stashes[k[3:]])
        else:
            return self.stashes[k]

    def __dir__(self):
        return sorted(dir(super(PathGroup, self)) + [ 'mp_'+k for k in self.stashes.keys() ])

    #
    # Interface
    #

    def step(self, n=None, step_func=None, stash=None, successor_func=None, until=None):
        stash = 'active' if stash is None else stash
        n = n if n is not None else 1 if until is None else 100000
        pg = self

        for i in range(n):
            l.debug("Round %d: stepping %s", i, pg)

            pg = pg._one_step(stash=stash, successor_func=successor_func)
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
        to_stash = 'pruned' if to_stash is None else to_stash
        from_stash = 'active' if from_stash is None else from_stash

        filter_func = (lambda p: True) if filter_func is None else filter_func
        to_prune, new_active = self._filter_paths(filter_func, self.stashes[from_stash])
        new_stashes = self._copy_stashes()

        for p in to_prune:
            if not p.state.satisfiable():
                new_stashes[to_stash].append(p)
                self._hierarchy.unreachable(p)
            else:
                new_active.append(p)

        return self._successor(new_stashes)

    def stash(self, filter_func, from_stash=None, to_stash=None):
        to_stash = 'stashed' if to_stash is None else to_stash
        from_stash = 'active' if from_stash is None else from_stash

        new_stashes = self._copy_stashes()
        self._move(new_stashes, filter_func, from_stash, to_stash)
        return self._successor(new_stashes)

    def drop(self, filter_func, stash=None):
        stash = 'active' if stash is None else stash

        new_stashes = self._copy_stashes()
        if stash in new_stashes:
            dropped, new_stash = self._filter_paths(filter_func, new_stashes[stash])
            new_stashes[stash] = new_stash
        else:
            dropped = [ ]

        l.debug("Dropping %d paths.", len(dropped))
        return self._successor(new_stashes)

    def unstash(self, filter_func, to_stash=None, from_stash=None, except_stash=None):
        to_stash = 'active' if to_stash is None else to_stash
        from_stash = 'stashed' if from_stash is None else from_stash

        l.debug("Unstashing from stash %s to stash %s", from_stash, to_stash)

        new_stashes = self._copy_stashes()

        for k in new_stashes.keys():
            if k == to_stash: continue
            elif except_stash is not None and k == except_stash: continue
            elif from_stash is not None and k != from_stash: continue

            l.debug("... checking stash %s with %d paths", k, len(new_stashes[k]))
            self._move(new_stashes, filter_func, k, to_stash)

        return self._successor(new_stashes)

    def merge(self, filter_func=None, merge_func=None, stash=None):
        stash = 'active' if stash is None else stash
        filter_func = self._condition_to_lambda(filter_func, default=True)

        to_merge, not_to_merge = self._filter_paths(filter_func, self.stashes[stash])

        merge_groups = [ ]
        while len(to_merge) > 0:
            g, to_merge = self._filter_paths(lambda p: p.addr == to_merge[0].addr, to_merge)
            if len(g) == 1:
                not_to_merge.append(g)
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
        return self.stash(lambda p: p.addr != addr, from_stash=from_stash, to_stash=to_stash)

    def stash_addr(self, addr, from_stash=None, to_stash=None):
        return self.stash(lambda p: p.addr == addr, from_stash=from_stash, to_stash=to_stash)

    def stash_addr_past(self, addr, from_stash=None, to_stash=None):
        return self.stash(lambda p: addr in p.addr_backtrace, from_stash=from_stash, to_stash=to_stash)

    def stash_not_addr_past(self, addr, from_stash=None, to_stash=None):
        return self.stash(lambda p: addr not in p.addr_backtrace, from_stash=from_stash, to_stash=to_stash)

    def stash_all(self, from_stash=None, to_stash=None):
        return self.stash(lambda p: True, from_stash=from_stash, to_stash=to_stash)

    def unstash_addr(self, addr, from_stash=None, to_stash=None, except_stash=None):
        return self.unstash(lambda p: p.addr == addr, from_stash=from_stash, to_stash=to_stash, except_stash=except_stash)

    def unstash_addr_past(self, addr, from_stash=None, to_stash=None, except_stash=None):
        return self.unstash(lambda p: addr in p.addr_backtrace, from_stash=from_stash, to_stash=to_stash, except_stash=except_stash)

    def unstash_not_addr(self, addr, from_stash=None, to_stash=None, except_stash=None):
        return self.unstash(lambda p: p.addr != addr, from_stash=from_stash, to_stash=to_stash, except_stash=except_stash)

    def unstash_not_addr_past(self, addr, from_stash=None, to_stash=None, except_stash=None):
        return self.unstash(lambda p: addr not in p.addr_backtrace, from_stash=from_stash, to_stash=to_stash, except_stash=except_stash)

    def unstash_all(self, from_stash=None, to_stash=None, except_stash=None):
        return self.unstash(lambda p: True, from_stash=from_stash, to_stash=to_stash, except_stash=except_stash)

    #
    # High-level functionality
    #

    def explore(self, stash=None, n=None, find=None, avoid=None, num_find=None, found_stash=None, avoid_stash=None):
        find = self._condition_to_lambda(find)
        avoid = self._condition_to_lambda(avoid)
        found_stash = 'found' if found_stash is None else found_stash
        avoid_stash = 'avoid' if avoid_stash is None else avoid_stash
        num_find = 1 if num_find is None else num_find
        cur_found = len(self.stashes[found_stash]) if found_stash in self.stashes else 0

        explore_step_func = lambda pg: pg.stash(find, from_stash=stash, to_stash=found_stash) \
                                         .stash(avoid, from_stash=stash, to_stash=avoid_stash)
        until_func = lambda pg: len(pg.stashes[found_stash]) >= cur_found + num_find
        return self.step(n=n, step_func=explore_step_func, until=until_func, stash=stash)

from .path_hierarchy import PathHierarchy
from .errors import PathUnreachableError
