#!/usr/bin/env python

import logging
l = logging.getLogger("angr.path")

from os import urandom
import collections

import mulpyplexer


class CallFrame(object):
    """
        Instance variables:
        Int             from address
        Int             to address
        claripy.E       pointer to from_addr
    """
    def __init__(self, faddr, taddr, sptr):
        """
        Int-> CallFrame
        Create a new CallFrame with the given arguments
        """
        self.faddr = faddr
        self.taddr = taddr
        self.sptr = sptr

class CallStack(object):
    """
        Instance variables:
        List        List of CallFrame
    """
    def __init__(self):
        """
        -> CallStack
        Create a new CallStack
        """
        self.callstack = []

    def __iter__(self):
        """
        -> Generator
        Overriding, for using the CallStack with iterators
        """
        for cf in self.callstack:
            yield cf

    def push(self, cf):
        """
        CallFrame ->
        Add the given CallFrame to the list of CallFrames
        """
        self.callstack.append(cf)

    def pop(self):
        """
        -> CallFrame
        Pop a CallFrame from the list
        """
        try:
            return self.callstack.pop()
        except IndexError:
            raise IndexError("pop from empty CallStack")

    def __len__(self):
        """
        -> Int
        Return the length of the stuff
        """
        return len(self.callstack)

class Path(object):
    def __init__(self, project, state, jumpkind='Ijk_Boring', path=None, run=None):
        # this is the state of the path
        self.state = state

        # project
        self._project = project

        # the address (integer)
        addr_expr = self.state.regs.ip
        if not self.state.se.unique(addr_expr):
            raise AngrPathError("Path created with a multivalued instruction pointer.")
        self.addr = self.state.se.any_int(addr_expr)

        # this path's information
        self.length = 0
        self.extra_length = 0

        self.jumpkind = jumpkind
        self.backtrace = [ ]
        self.addr_backtrace = [ ]
        self.callstack = CallStack()
        self.blockcounter_stack = [ collections.Counter() ]
        self.targets = [ ]
        self.guards = [ ]
        self.sources = [ ]
        self.jumpkinds = [ ]
        self.previous_run = None

        # the log
        self.events = [ ]
        self.actions = [ ]
        self.last_events = [ ]
        self.last_actions = [ ]
        self.fresh_variables = [ ]

        # for merging
        self._upcoming_merge_points = [ ]
        self._merge_flags = [ ]
        self._merge_values = [ ]
        self._merge_backtraces = [ ]
        self._merge_addr_backtraces = [ ]
        self._merge_depths = [ ]

        # copy a path if it's given
        if path is not None:
            self._record_path(path)

        # for printing/ID stuff and inheritence
        self.name = str(id(self))
        self.path_id = urandom(8).encode('hex')

        # Whitelist and last_stmt used for executing program slices
        self.stmt_whitelist = None
        self.last_stmt = None

        # actual analysis stuff
        self._run = None
        self._successors = None
        self._error = None
        self._reachable = None

        # if a run is provided, record it
        if run is not None:
            self._record_run(run)
            self._record_state(self.state)

    @property
    def unconstrained_successor_states(self):
        return self.next_run.unconstrained_successors

    def divergence_addr(self, other):
        '''
        Returns the basic block at which the paths diverged.

        @param other: the other Path
        @returns an address (long)
        '''

        for i in range(max([len(self.addr_backtrace), len(other.addr_backtrace)])):
            if i > len(self.addr_backtrace):
                return other.addr_backtrace[i-1]
            elif i > len(other.addr_backtrace):
                return self.addr_backtrace[i-1]
            elif self.addr_backtrace[i] != other.addr_backtrace[i]:
                return self.addr_backtrace[i-1]


    def detect_loops(self, n=None): #pylint:disable=unused-argument
        '''
        Returns the current loop iteration that a path is on.

        @param n: the minimum number of iterations to check for.
        @returns the number of the loop iteration it's in
        '''

        # TODO: make this work better
        #addr_strs = [ "%x"%x for x in self.addr_backtrace ]
        #bigstr = "".join(addr_strs)

        #candidates = [ ]

        #max_iteration_length = len(self.addr_backtrace) / n
        #for i in range(max_iteration_length):
        #   candidates.append("".join(addr_strs[-i-0:]))

        #for c in reversed(candidates):
        #   if bigstr.count(c) >= n:
        #       return n
        #return None

        mc = self.blockcounter_stack[-1].most_common()
        if len(mc) == 0:
            return None
        else:
            return mc[0][1]

    def _make_sim_run(self):
        self._run = self._project.sim_run(self.state, stmt_whitelist=self.stmt_whitelist, last_stmt=self.last_stmt, jumpkind=self.jumpkind)

    def make_sim_run_with_size(self, size):
        self._run = self._project.sim_run(self.state, stmt_whitelist=self.stmt_whitelist, last_stmt=self.last_stmt,
                                          jumpkind=self.jumpkind, max_size=size)

    @property
    def next_run(self):
        if self._run is None:
            self._make_sim_run()
        return self._run

    @property
    def successors(self):
        if self._successors is None:
            self._successors = [ ]
            for s in self.next_run.flat_successors:
                jk = self.next_run.irsb.jumpkind if hasattr(self.next_run, 'irsb') else 'Ijk_Boring'
                sp = Path(self._project, s, path=self, run=self.next_run, jumpkind=jk)
                self._successors.append(sp)
        return self._successors

    @property
    def mp_successors(self):
        return mulpyplexer.MP(self.successors)


    #
    # Error checking
    #

    _jk_errors = set(("Ijk_EmFail", "Ijk_NoDecode", "Ijk_MapFail"))
    _jk_signals = set(('Ijk_SigILL', 'Ijk_SigTRAP', 'Ijk_SigSEGV', 'Ijk_SigBUS', 'Ijk_SigFPE_IntDiv', 'Ijk_SigFPE_IntOvf'))
    _jk_all_bad = _jk_errors | _jk_signals

    @property
    def error(self):
        if self._error is not None:
            return self._error
        elif len(self.jumpkinds) > 0 and self.jumpkinds[-1] in Path._jk_all_bad:
            l.debug("Errored jumpkind %s", self.jumpkinds[-1])
            self._error = AngrPathError('path has a failure jumpkind of %s' % self.jumpkinds[-1])
        else:
            try:
                self._make_sim_run()
            except (AngrError, simuvex.SimError, claripy.ClaripyError) as e:
                l.debug("Catching exception", exc_info=True)
                self._error = e
            except (TypeError, ValueError, ArithmeticError, MemoryError) as e:
                l.debug("Catching exception", exc_info=True)
                self._error = e

        return self._error

    @error.setter
    def error(self, e):
        self._error = e

    @property
    def errored(self):
        return self.error is not None

    #
    # Reachability checking, by popular demand (and necessity)!
    #

    @property
    def reachable(self):
        if self._reachable is None:
            self._reachable = self.state.satisfiable()

        return self._reachable

    @property
    def weighted_length(self):
        return self.length + self.extra_length

    #
    # Convenience functions
    #

    @property
    def _r(self):
        return self.next_run

    @property
    def _s0(self):
        return self.successors[0]
    @property
    def _s1(self):
        return self.successors[1]
    @property
    def _s2(self):
        return self.successors[2]
    @property
    def _s3(self):
        return self.successors[3]

    def descendant(self, n):
        p = self
        for _ in range(n):
            p = p._s0
        return p

    #
    # State continuation
    #

    def _record_path(self, path):
        self.last_events = list(path.last_events)
        self.last_actions = list(path.last_actions)
        self.events.extend(path.events)
        self.actions.extend(path.actions)

        self.backtrace.extend(path.backtrace)
        self.addr_backtrace.extend(path.addr_backtrace)
        self.callstack.callstack.extend(path.callstack.callstack)

        self.guards.extend(path.guards)
        self.sources.extend(path.sources)
        self.jumpkinds.extend(path.jumpkinds)
        self.targets.extend(path.targets)

        self.length = path.length
        self.extra_length = path.extra_length
        self.previous_run = path.next_run

        self.blockcounter_stack = [ collections.Counter(s) for s in path.blockcounter_stack ]
        self._upcoming_merge_points = list(path._upcoming_merge_points)
        self._merge_flags = list(path._merge_flags)
        self._merge_values = list(path._merge_values)
        self._merge_backtraces = list(path._merge_backtraces)
        self._merge_addr_backtraces = list(path._merge_addr_backtraces)
        self._merge_depths = list(path._merge_depths)

    def _record_state(self, state):
        '''
        Adds the information from the last run to the current path.
        '''

        l.debug("Extending path with state %s", state)

        self.last_events = list(state.log.events)
        self.last_actions = list(e for e in state.log.events if isinstance(e, simuvex.SimAction))
        self.events.extend(self.last_events)
        self.actions.extend(self.last_actions)

        self.jumpkinds.append(state.scratch.jumpkind)
        self.targets.append(state.scratch.target)
        self.guards.append(state.scratch.guard)
        self.sources.append(state.scratch.source)

        # maintain the blockcounter stack
        if self.jumpkinds[-1] == "Ijk_Call":
            l.debug("... it's a call!")
            sp = self.state.regs.sp
            callframe = CallFrame(state.scratch.bbl_addr, state.scratch.bbl_addr, sp)
            self.callstack.push(callframe)
            self.blockcounter_stack.append(collections.Counter())
        elif self.jumpkinds[-1] == "Ijk_Ret":
            l.debug("... it's a ret!")
            self.blockcounter_stack.pop()
            if len(self.blockcounter_stack) == 0:
                l.debug("... WARNING: unbalanced callstack")
                self.blockcounter_stack.append(collections.Counter())

            if len(self.callstack) > 0:
                self.callstack.pop()

        self.addr_backtrace.append(state.scratch.bbl_addr)
        self.blockcounter_stack[-1][state.scratch.bbl_addr] += 1
        self.length += 1

    def _record_run(self, run):
        '''
        Adds the information from the last run to the current path.
        '''
        l.debug("Extending path with run %s", run)

        # maintain the blockstack
        self.backtrace.append(str(run))

    #
    # Merging and splitting
    #

    def unmerge(self):
        '''
        Unmerges the state back into different possible states.
        '''

        l.debug("Unmerging %s!", self)

        states = [ self.state ]

        for flag,values in zip(self._merge_flags, self._merge_values):
            l.debug("... processing %s with %d possibilities", flag, len(values))

            new_states = [ ]

            for v in values:
                for s in states:
                    s_copy = s.copy()
                    s_copy.add_constraints(flag == v)
                    new_states.append(s_copy)

            states = [ s for s in new_states if s.satisfiable() ]
            l.debug("... resulting in %d satisfiable states", len(states))

        new_paths = [ ]
        for s in states:
            s.simplify()

            p = Path(self._project, s, path=self)
            new_paths.append(p)
        return new_paths

    def merge(self, *others):
        '''
        Returns a merger of this path with *others.
        '''
        all_paths = list(others) + [ self ]
        if len(set([ o.addr for o in all_paths])) != 1:
            raise AngrPathError("Unable to merge paths.")

        # merge the state
        new_state, merge_flag, _ = self.state.merge(*[ o.state for o in others ])
        new_path = Path(self._project, new_state, path=self)

        # fix the backtraces
        divergence_index = [ len(set(addrs)) == 1 for addrs in zip(*[ o.addr_backtrace for o in all_paths ]) ].index(False)
        new_path.addr_backtrace = self.addr_backtrace[:divergence_index]
        new_path.addr_backtrace.append(-1)
        new_path.backtrace = self.backtrace[:divergence_index]
        new_path.backtrace.append(("MERGE POINT: %s" % merge_flag))

        # reset the upcoming merge points
        new_path._upcoming_merge_points = [ ]
        new_path._merge_flags.append(merge_flag)
        new_path._merge_values.append(list(range(len(all_paths))))
        new_path._merge_backtraces.append( [ o.backtrace for o in all_paths ] )
        new_path._merge_addr_backtraces.append( [ o.addr_backtrace for o in all_paths ] )
        new_path._merge_depths.append(new_path.length) #

        return new_path

    def __repr__(self):
        return "<Path with %d runs (at 0x%x)>" % (len(self.backtrace), self.addr)

from .errors import AngrError, AngrPathError
import simuvex
import claripy
