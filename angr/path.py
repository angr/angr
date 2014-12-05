#!/usr/bin/env python

import logging
l = logging.getLogger("angr.path")

from .errors import AngrPathError
import simuvex
from os import urandom

import cPickle as pickle
import collections


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
    def __init__(self, project, state, path=None, run=None):
        # this is the state of the path
        self.state = state

        # project
        self._project = project

        # the address (integer)
        addr_expr = self.state.reg_expr('ip')
        if not self.state.se.unique(addr_expr):
            raise AngrPathError("Path created with a multivalued instruction pointer.")
        self.addr = self.state.se.any_int(addr_expr)

        # this path's information
        self.length = 0
        self.events = [ ]
        self.backtrace = [ ]
        self.addr_backtrace = [ ]
        self.callstack = CallStack()
        self.blockcounter_stack = [ collections.Counter() ]
        self.guards = [ ]
        self.sources = [ ]
        self.jumpkinds = [ ]

        # for merging
        self._upcoming_merge_points = [ ]
        self._merge_flags = [ ]
        self._merge_values = [ ]
        self._merge_backtraces = [ ]
        self._merge_addr_backtraces = [ ]
        self._merge_depths = [ ]

        # copy a path if it's given
        if path is not None:
            self.events.extend(path.events)
            self.backtrace.extend(path.backtrace)
            self.addr_backtrace.extend(path.addr_backtrace)
            self.callstack.callstack.extend(path.callstack.callstack)
            self.guards.extend(path.guards)
            self.sources.extend(path.sources)
            self.jumpkinds.extend(path.jumpkinds)

            self.length = path.length + 1

            self.blockcounter_stack = [ collections.Counter(s) for s in self.blockcounter_stack ]
            self._upcoming_merge_points = list(self._upcoming_merge_points)
            self._merge_flags = list(self._merge_flags)
            self._merge_values = list(self._merge_values)
            self._merge_backtraces = list(self._merge_backtraces)
            self._merge_addr_backtraces = list(self._merge_addr_backtraces)
            self._merge_depths = list(self._merge_depths)

        # for printing/ID stuff and inheritence
        self.name = str(id(self))
        self.path_id = urandom(8).encode('hex')

        # actual analysis stuff
        self._run = None
        self._successors = None

        # if a run is provided, record it
        if run is not None:
            self._record_run(run)

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

        return self.blockcounter_stack[-1].most_common()[0][1]

    @property
    def last_run(self):
        if self._run is None:
            self._run = self._project.sim_run(self.state)
        return self._run

    @property
    def successors(self):
        if self._successors is None:
            self._successors = [ ]
            for s in self.last_run.flat_successors:
                sp = Path(self._project, s, path=self, run=self.last_run)
                self._successors.append(sp)
        return self._successors

    def _record_run(self, run):
        '''
        Adds the information fromt the last run to the current path.
        '''
        l.debug("Extending path with: %s", run)

        self.events.extend(run.initial_state.log.events)
        self.jumpkinds.append(run.initial_state.log.jumpkind)
        self.guards.append(run.initial_state.log.guard)
        self.sources.append(run.initial_state.log.source)

        # maintain the blockcounter stack
        if self.jumpkinds[-1] == "Ijk_Call":
            l.debug("... it's a call!")
            sp = self.state.reg_expr("sp")
            callframe = CallFrame(run.addr, run.addr, sp)
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

        # maintain the blockstack
        self.backtrace.append(str(run))
        self.addr_backtrace.append(run.addr)
        self.blockcounter_stack[-1][run.addr] += 1

        self.length += 1

    @property
    def _r(self):
        return self.last_run

    #
    # Merging and splitting
    #

    def unmerge(self):
        '''
        Unmerges the state back into different possible states.
        '''

        l.debug("Unmerging %s!", self)

        states = [ self.last_initial_state ]

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

            p = self.copy()
            p.last_run = self.last_run.reanalyze(new_state=s)
            new_paths.append(p)
        return new_paths

    def merge(self, *others):
        '''
        Returns a merger of this path with *others.
        '''
        all_paths = list(others) + [ self ]
        if len(set([ o.last_addr for o in all_paths])) != 1:
            raise AngrPathError("Unable to merge paths.")

        self.add_event(PathEventMessage("info", "merging..."))

        # merge the state
        new_path = self.copy()
        new_state, merge_flag, _ = self.last_initial_state.merge(*[ o.last_initial_state for o in others ])

        # fix the backtraces
        divergence_index = [ len(set(addrs)) == 1 for addrs in zip(*[ o.addr_backtrace for o in all_paths ]) ].index(False)
        new_path.addr_backtrace = self.addr_backtrace[:divergence_index]
        new_path.addr_backtrace.append(-1)
        new_path.backtrace = self.backtrace[:divergence_index]
        new_path.backtrace.append(("MERGE POINT: %s" % merge_flag))

        # continue the path
        e = simuvex.SimExit(state=new_state, addr=self.last_addr, state_is_raw=True)
        new_path.continue_through_exit(e, copy=False)

        # reset the upcoming merge points
        new_path._upcoming_merge_points = [ ]
        new_path._merge_flags.append(merge_flag) # pylint: disable=W0212,
        new_path._merge_values.append(list(range(len(all_paths)))) # pylint: disable=W0212,
        new_path._merge_backtraces.append( [ o.backtrace for o in all_paths ] ) # pylint: disable=W0212,
        new_path._merge_addr_backtraces.append( [ o.addr_backtrace for o in all_paths ] ) # pylint: disable=W0212,
        new_path._merge_depths.append(new_path.length) # pylint: disable=W0212,

        return new_path

    def suspend(self, do_pickle=True):
        '''
        Suspends the path for spilling/pickling.
        '''
        l.debug("%s suspending...", self)

        if do_pickle:
            self._pickle_state_id = id(self.last_initial_state)
            self._pickle_addr = self.last_addr
            self._pickle_whitelist = getattr(self.last_run, 'whitelist', None)
            self._pickle_last_stmt = getattr(self.last_run, 'last_stmt', None)

            l.debug("... pickling the initial state")
            pickle.dump(self.last_initial_state, open("pickle/state-%d.p" % self._pickle_state_id, "w"))

            l.debug("... deleting everything!")
            self.last_run = None
            self._entry = None
            self._project = None
        else:
            if self.last_run is not None:
                for e in self.last_run.exits():
                    e.downsize()
                self.last_initial_state.downsize()

    def __repr__(self):
        return "<Path with %d runs (at 0x%x)>" % (len(self.backtrace), self.addr)
