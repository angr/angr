import ana
import simuvex

import logging
l = logging.getLogger('angr.path_group')
l.setLevel('DEBUG')


class PathGroup(ana.Storable):
    def __init__(self, project, paths, stashes=None, heirarchy=None, immutable=True):
        self._project = project
        self._heirarchy = PathHeirarchy() if heirarchy is None else heirarchy
        self._immutable = immutable

        self.active = paths
        self.stashes = { 'pruned': [ ], 'errored': [ ], 'deadended': [ ] } if stashes is None else stashes

    def _copy_stashes(self):
        if self._immutable:
            return { k:list(v) for k,v in self.stashes.items() }
        else:
            return self.stashes

    def _successor(self, new_active, new_stashes):
        if not self._immutable:
            self.active = new_active
            self.stashes = new_stashes
            return self
        else:
            return PathGroup(self._project, new_active, new_stashes, heirarchy=self._heirarchy, immutable=self._immutable)

    @staticmethod
    def _condition_to_lambda(condition):
        if condition is None:
            condition = lambda p: False

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

    def _one_step(self):
        new_stashes = self._copy_stashes()
        new_active = [ ]

        for a in self.active:
            if a.errored:
                if isinstance(a.error, PathUnreachableError):
                    new_stashes['pruned'].append(a)
                else:
                    self._heirarchy.unreachable(a)
                    new_stashes['errored'].append(a)
            elif len(a.successors) == 0:
                new_stashes['deadended'].append(a)
            else:
                new_active.extend(a.successors)

        return self._successor(new_active, new_stashes)

    def step(self, n=1, step_func=None):
        pg = self

        for i in range(n):
            l.debug("Round %d: stepping %s", i, pg)

            pg = pg._one_step()
            if step_func is not None:
                pg = step_func(pg)

            if len(pg.active) == 0:
                break

        return pg

    def prune(self, filter_func=None, stash=None):
        filter_func = (lambda p: True) if filter_func is None else filter_func
        stash = 'pruned' if stash is None else stash
        to_prune, new_active = self._filter_paths(filter_func, self.active)
        new_stashes = self._copy_stashes()

        for p in to_prune:
            if not p.state.satisfiable():
                new_stashes['pruned'].append(p)
                self._heirarchy.unreachable(p)
            else:
                new_active.append(p)

        return self._successor(new_active, new_stashes)

    def stash(self, filter_func, stash=None):
        stash = 'stashed' if stash is None else stash

        to_stash, new_active = self._filter_paths(filter_func, self.active)

        new_stashes = self._copy_stashes()
        if stash not in new_stashes: new_stashes[stash] = [ ]
        new_stashes[stash].extend(to_stash)

        return self._successor(new_active, new_stashes)

    def drop(self, filter_func, stash=None):
        if stash is None:
            dropped, new_active = self._filter_paths(filter_func, self.active)
            new_stashes = self._copy_stashes()
        else:
            new_active = list(self.active)
            new_stashes = self._copy_stashes()
            if stash in new_stashes:
                dropped, new_stash = self._filter_paths(filter_func, new_stashes[stash])
                new_stashes[stash] = new_stash
            else:
                dropped = [ ]

        l.debug("Dropping %d paths.", len(dropped))
        return self._successor(new_active, new_stashes)

    def unstash(self, filter_func, stash=None, except_stash=None):
        new_stashes = self._copy_stashes()

        new_active = list(self.active)
        for k,s in self.stashes.items():
            if stash is not None and k != stash: continue
            if except_stash is not None and k == except_stash: continue

            to_unstash, keep_stashed = self._filter_paths(filter_func, s)
            new_stashes[k] = keep_stashed
            new_active.extend(to_unstash)

        return self._successor(new_active, new_stashes)

    def merge(self, filter_func):
        to_merge, new_active = self._filter_paths(filter_func, self.active)

        merge_groups = [ ]
        while len(to_merge) > 0:
            g, to_merge = self._filter_paths(lambda p: p.addr == to_merge[0].addr, to_merge)
            if len(g) == 1:
                new_active.append(g)
            merge_groups.append(g)

        for g in merge_groups:
            try:
                m = g[0].merge(*g[1:])
                new_active.append(m)
            except simuvex.SimMergeError:
                l.warning("SimMergeError while merging %d paths", len(g), exc_info=True)
                new_active.extend(g)

        return self._successor(new_active, self._copy_stashes())

    def __repr__(self):
        s = "<PathGroup with %d active" % len(self.active)
        for k,v in self.stashes.items():
            s += ", %d %s" % (len(v), k)
        s += ">"
        return s

    #
    # Various canned functionality
    #

    def stash_not_addr_current(self, addr, stash=None):
        return self.stash(lambda p: p.addr != addr, stash=stash)

    def stash_addr_current(self, addr, stash=None):
        return self.stash(lambda p: p.addr == addr, stash=stash)

    def stash_addr_past(self, addr, stash=None):
        return self.stash(lambda p: addr in p.addr_backtrace, stash=stash)

    def stash_not_addr_past(self, addr, stash=None):
        return self.stash(lambda p: addr not in p.addr_backtrace, stash=stash)

    def stash_all(self, stash=None):
        return self.stash(lambda p: True, stash=stash)

    def unstash_addr_current(self, addr, stash=None, except_stash=None):
        return self.unstash(lambda p: p.addr == addr, stash=stash, except_stash=except_stash)

    def unstash_addr_past(self, addr, stash=None, except_stash=None):
        return self.unstash(lambda p: addr in p.addr_backtrace, stash=stash, except_stash=except_stash)

    def unstash_not_addr_current(self, addr, stash=None, except_stash=None):
        return self.unstash(lambda p: p.addr != addr, stash=stash, except_stash=except_stash)

    def unstash_not_addr_past(self, addr, stash=None, except_stash=None):
        return self.unstash(lambda p: addr not in p.addr_backtrace, stash=stash, except_stash=except_stash)

    def unstash_all(self, stash=None, except_stash=None):
        return self.unstash(lambda p: True, stash=stash, except_stash=except_stash)

    #
    # High-level functionality
    #

    def explore(self, n=1000, find=None, avoid=None):
        find = self._condition_to_lambda(find)
        avoid = self._condition_to_lambda(find)
        explore_step_func = lambda pg: pg.stash(find, 'found').stash(avoid, 'avoided')
        return self.step(n=n, step_func=explore_step_func)

from .path_heirarchy import PathHeirarchy
from .errors import PathUnreachableError
