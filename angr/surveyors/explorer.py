#!/usr/bin/env python

from ..surveyor import Surveyor
import simuvex

import collections
import networkx
import logging
l = logging.getLogger("angr.surveyors.explorer")

class Explorer(Surveyor):
    """
    Explorer implements a symbolic exploration engine!

    WARNING: Explorers are not really maintained - Use path_group instead when possible

    found - paths where the target addresses have been found.
    avoided - paths where the to-avoid addresses have been found.
    deviating - paths that deviate from the restricted-to addresses.
    looping - paths that were detected as looping.
    """

    path_lists = Surveyor.path_lists + [ 'found', 'avoided', 'deviating', 'looping']

    def __init__(self, project, start=None, max_concurrency=None, max_active=None, pickle_paths=None,
                 find=None, avoid=None, restrict=None, min_depth=0, max_depth=None, max_repeats=10000000,
                 num_find=1, num_avoid=None, num_deviate=1, num_loop=None, cfg=None, enable_veritesting=None,
                 veritesting_options=None, keep_pruned=None):
        """
        Explores the path space until a block containing a specified address is found.

        :param project:

        The following parameters are optional :

        :param start:
        :param max_concurrency:
        :param max_active:
        :param pickle_paths:
        :param find:                A tuple containing the addresses to search for.
        :param avoid:               A tuple containing the addresses to avoid.
        :param restrict:            A tuple containing the addresses to restrict the analysis to (avoid all others).
        :param min_depth:           The minimum number of SimRuns in the resulting path.
        :param max_depth:           The maximum number of SimRuns in the resulting path.
        :param num_find:            The minimum number of paths to find. (default: 1)
        :param num_avoid:           The minimum number of paths to avoid. (default: infinite)
        :param num_deviate:         The minimum number of paths to deviate. (default: infinite)
        :param num_loop:            The minimum number of paths to loop (default: infinite)
        :param cfg:                 A CFG to use to cut any paths that have no chance of going to the target.
        :param enable_veritesting:  Whether Veritesting should be enabled or not.
        :param veritesting_options: Options that should be passed to Veritesting.
        """
        Surveyor.__init__(self,
                          project,
                          start=start,
                          max_concurrency=max_concurrency,
                          max_active=max_active,
                          pickle_paths=pickle_paths,
                          enable_veritesting=enable_veritesting,
                          veritesting_options=veritesting_options,
                          keep_pruned=keep_pruned)

        # initialize the counter
        self._instruction_counter = collections.Counter()

        self._find = find if not isinstance(find, (int, long)) else [find]
        self._avoid = avoid
        self._restrict = restrict
        self._max_repeats = max_repeats
        self._max_depth = max_depth
        self._min_depth = min_depth

        self.found = [ ]
        self.avoided = [ ]
        self.deviating = [ ]
        self.looping = [ ]
        self.lost = [ ]

        self._num_find = num_find
        self._num_avoid = num_avoid
        self._num_deviate = num_deviate
        self._num_loop = num_loop

        self._cfg = cfg

        if self._cfg is not None and isinstance(self._find, (tuple, set, list)):
            good_find = set()
            for f in self._find:
                if self._cfg.get_any_irsb(f) is None:
                    l.warning("No node 0x%x in CFG. This will be automatically cut.", f)
                else:
                    good_find.add(f)
            self._find = good_find

        if self._project.arch.name.startswith('ARM'):
            self._find = [x & ~1 for x in self._find] + [x | 1 for x in self._find]

    def iter_found(self, runs=None):
        runs = -1 if runs is None else runs

        cur_found = 0
        while runs != 0:
            self.run(1)
            for f in self.found[cur_found:]:
                l.debug("Yielding found path %s", f)
                yield f

            cur_found = len(self.found)
            runs -= 1
            if self.done:
                break

    __iter__ = iter_found

    @property
    def _f(self):
        return self.found[0]

    @property
    def _av(self):
        return self.avoided[0]

    @property
    def _dv(self):
        return self.deviating[0]

    @property
    def _lo(self):
        return self.looping[0]

    def path_comparator(self, x, y):
        return self._instruction_counter[x.addr] - self._instruction_counter[y.addr]

    @property
    def done(self):
        if len(self.active) == 0:
            l.debug("Done because we have no active paths left!")
            return True

        if self._num_find is not None and len(self.found) >= self._num_find:
            l.debug("Done because we found the targets on %d path(s)!", len(self.found))
            return True

        if self._num_avoid is not None and len(self.avoided) >= self._num_avoid:
            l.debug("Done because we avoided on %d path(s)!", len(self.avoided))
            return True

        if self._num_deviate is not None and len(self.deviating) >= self._num_deviate:
            l.debug("Done because we deviated on %d path(s)!", len(self.deviating))
            return True

        if self._num_loop is not None and len(self.looping) >= self._num_loop:
            l.debug("Done because we looped on %d path(s)!", len(self.looping))
            return True

        return False

    def _match(self, criteria, path, imark_set): #pylint:disable=no-self-use
        if criteria is None:
            r = False
        elif isinstance(criteria, set):
            r = len(criteria & imark_set) > 0
        elif isinstance(criteria, (tuple, list)):
            r = len(set(criteria) & imark_set) > 0
        elif isinstance(criteria, (int, long)):
            r = criteria in imark_set
        elif hasattr(criteria, '__call__'):
            r = criteria(path)

        return r

    def _restricted(self, criteria, path, imark_set): #pylint:disable=no-self-use
        if criteria is None:
            r = False
        elif isinstance(criteria, set):
            r = not imark_set.issubset(criteria)
        elif isinstance(criteria, (tuple, list)):
            r = not imark_set.issubset(set(criteria))
        elif isinstance(criteria, (int, long)):
            r = criteria in imark_set
        elif hasattr(criteria, '__call__'):
            r = criteria(path)

        return r

    def _is_lost(self, p):
        if self._cfg is None:
            return False
        elif not isinstance(self._find, (tuple, set, list)) or len(self._find) == 0:
            l.warning("Explorer ignoring CFG because find is not a sequence of addresses.")
            return False
        elif isinstance(self._cfg.get_any_irsb(p.addr), simuvex.SimProcedure):
            l.debug("Path %s is pointing to a SimProcedure. Counting as not lost.", p)
            return False
        elif p.length > 0 and self._cfg.get_any_irsb(p.addr_trace[-1]) is None:
            l.debug("not trimming, because %s is currently outside of the CFG", p)
            return False
        else:
            f = self._cfg.get_any_irsb(p.addr)
            if f is None:
                l.warning("CFG has no node at 0x%x. Cutting this path.", p.addr)
                return False
            if not any(((networkx.has_path(self._cfg._graph, f, self._cfg.get_any_irsb(t)) for t in self._find))):
                l.debug("Trimming %s because it can't get to the target (according to the CFG)", p)
                return True
            else:
                l.debug("Not trimming %s, because it can still get to the target.", p)
                return False

    def filter_path(self, p):
        if self._is_lost(p):
            l.debug("Cutting path %s because it's lost.", p)
            self.lost.append(p)
            return False

        if p.length < self._min_depth:
            l.debug("path %s has less than the minimum depth", p)
            return True

        if not self._project.is_hooked(p.addr):
            try:
                imark_set = set(self._project.factory.block(p.addr).instruction_addrs)
            except (AngrMemoryError, AngrTranslationError):
                l.debug("Cutting path because there is no code at address 0x%x", p.addr)
                self.errored.append(p)
                return False
        else:
            imark_set = { p.addr }

        for addr in imark_set:
            self._instruction_counter[addr] += 1

        if self._match(self._avoid, p, imark_set):
            l.debug("Avoiding path %s.", p)
            self.avoided.append(p)
            return False
        elif self._match(self._find, p, imark_set):
            if not p.state.satisfiable():
                l.debug("Discarding 'found' path %s because it is unsat", p)
                self.deadended.append(p)
                return False

            l.debug("Marking path %s as found.", p)
            self.found.append(p)
            return False
        elif self._restricted(self._restrict, p, imark_set):
            l.debug("Path %s is not on the restricted addresses!", p)
            self.deviating.append(p)
            return False
        elif p.detect_loops(self._max_repeats) >= self._max_repeats:
            # discard any paths that loop too much
            l.debug("Path %s appears to be looping!", p)
            self.looping.append(p)
            return False
        elif self._max_depth is not None and p.length > self._max_depth:
            l.debug('Path %s exceeds the maximum depth(%d) allowed.', p, self._max_depth)
            return False
        else:
            l.debug("Letting path %s continue", p)
            return True

    def __repr__(self):
        return "<Explorer with paths: %s, %d found, %d avoided, %d deviating, %d looping, %d lost>" % (
        Surveyor.__repr__(self), len(self.found), len(self.avoided), len(self.deviating), len(self.looping),
        len(self.lost))

from ..errors import AngrMemoryError, AngrTranslationError

from . import all_surveyors
all_surveyors['Explorer'] = Explorer
