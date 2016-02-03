import copy
import logging
l = logging.getLogger("angr.path")

from os import urandom
import collections

import mulpyplexer

#pylint:disable=unidiomatic-typecheck

class CallFrame(object):
    '''
    Stores the address of the function you're in and the value of SP
    at the VERY BOTTOM of the stack, i.e. points to the return address
    '''
    def __init__(self, state=None, func_addr=None, stack_ptr=None, ret_addr=None):
        '''
        Initialize with either a state or the function address,
        stack pointer, and return address
        '''
        if state is not None:
            self.func_addr = state.se.any_int(state.ip)
            self.stack_ptr = state.se.any_int(state.regs.sp)

            if state.arch.call_pushes_ret:
                self.ret_addr = state.memory.load(state.regs.sp, state.arch.bits/8, endness=state.arch.memory_endness)
            else:
                self.ret_addr = state.regs.lr
            self.ret_addr = state.se.any_int(self.ret_addr)
        else:
            self.func_addr = func_addr
            self.stack_ptr = stack_ptr
            self.ret_addr = ret_addr

        self.block_counter = collections.Counter()

    def __str__(self):
        return "Func %#x, sp=%#x, ret=%#x" % (self.func_addr, self.stack_ptr, self.ret_addr)

    def __repr__(self):
        return '<CallFrame (Func %#x)>' % (self.func_addr)

    def copy(self):
        c = CallFrame(None, self.func_addr, self.stack_ptr, self.ret_addr)
        c.block_counter = collections.Counter(self.block_counter)
        return c

class CallStack(object):
    def __init__(self):
        self._callstack = []

    def __iter__(self):
        """
        Iterate through the callstack, from top to bottom
        (most recent first)
        """
        for cf in reversed(self._callstack):
            yield cf

    def push(self, cf):
        self._callstack.append(cf)

    def pop(self):
        try:
            return self._callstack.pop(-1)
        except IndexError:
            raise ValueError("Empty CallStack")

    @property
    def top(self):
        try:
            return self._callstack[-1]
        except IndexError:
            raise ValueError("Empty CallStack")

    def __getitem__(self, k):
        '''
        Returns the CallFrame at index k, indexing from the top of the stack.
        '''
        k = -1 - k
        return self._callstack[k]

    def __len__(self):
        return len(self._callstack)

    def __repr__(self):
        return "<CallStack (depth %d)>" % len(self._callstack)

    def __str__(self):
        return "Backtrace:\n%s" % "\n".join(str(f) for f in self)

    def __eq__(self, other):
        if not isinstance(other, CallStack):
            return False

        if len(self) != len(other):
            return False

        for c1, c2 in zip(self._callstack, other._callstack):
            if c1.func_addr != c2.func_addr or c1.stack_ptr != c2.stack_ptr or c1.ret_addr != c2.ret_addr:
                return False

        return True

    def __ne__(self, other):
        return self != other

    def __hash__(self):
        return hash(tuple((c.func_addr, c.stack_ptr, c.ret_addr) for c in self._callstack))

    def copy(self):
        c = CallStack()
        c._callstack = [cf.copy() for cf in self._callstack]
        return c

class Path(object):
    def __init__(self, project, state, path=None):
        # this is the state of the path
        self.state = state
        self.errored = False

        # project
        self._project = project

        if path is None:
            # this path's information
            self.length = 0
            self.extra_length = 0

            # the path history
            self.trace = []
            self.addr_trace = []
            self.targets = []
            self.guards = []
            self.jumpkinds = []
            self.events = []
            self.actions = []
            self.callstack = CallStack()
            self.callstack.push(CallFrame(None, self.addr, self.state.se.any_int(self.state.regs.sp), 0))
            self.popped_callframe = None
            self.callstack_backtrace = []

            # the previous run
            self.previous_run = None
            self.last_events = []
            self.last_actions = []

            # A custom information store that will be passed to all its descendents
            self.info = {}

            # for merging
            self._upcoming_merge_points = []
            self._merge_flags = []
            self._merge_values = []
            self._merge_traces = []
            self._merge_addr_traces = []
            self._merge_depths = []

        else:
            # this path's information
            self.length = path.length + 1
            self.extra_length = path.extra_length

            # the path history
            self.trace = list(path.trace)
            self.addr_trace = list(path.addr_trace)
            self.targets = list(path.targets)
            self.guards = list(path.guards)
            self.jumpkinds = list(path.jumpkinds)
            self.events = list(path.events)
            self.actions = list(path.actions)
            self.callstack = path.callstack.copy()
            self.popped_callframe = path.popped_callframe
            self.callstack_backtrace = list(path.callstack_backtrace)

            # the previous run
            self.previous_run = path._run
            self.last_events = list(state.log.events)
            self.last_actions = list(e for e in state.log.events if isinstance(e, simuvex.SimAction))
            self._record_state(self.state)
            self._record_run(path._run)

            # A custom information store that will be passed to all its descendents
            self.info = { k:copy.copy(v) for k, v in path.info.iteritems() }

            self._upcoming_merge_points = list(path._upcoming_merge_points)
            self._merge_flags = list(path._merge_flags)
            self._merge_values = list(path._merge_values)
            self._merge_traces = list(path._merge_traces)
            self._merge_addr_traces = list(path._merge_addr_traces)
            self._merge_depths = list(path._merge_depths)

        # for printing/ID stuff and inheritence
        self.name = str(id(self))
        self.path_id = urandom(8).encode('hex')

        # actual analysis stuff
        self._run_args = None       # sim_run args, to determine caching
        self._run = None
        self._run_error = None
        self._reachable = None

    @property
    def addr(self):
        return self.state.se.any_int(self.state.regs.ip)

    #
    # Stepping methods and successor access
    #

    def step(self, **run_args):
        '''
        Step a path forward. Optionally takes any argument applicable
        to project.factory.sim_run:

        @param jumpkind: the jumpkind of the previous exit
        @param addr an address: to execute at instead of the state's ip
        @param stmt_whitelist: a list of stmt indexes to which to confine execution
        @param last_stmt: a statement index at which to stop execution
        @param thumb: whether the block should be lifted in ARM's THUMB mode
        @param backup_state: a state to read bytes from instead of using project memory
        @param opt_level: the VEX optimization level to use
        @param insn_bytes: a string of bytes to use for the block instead of the project
        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        '''
        if self._run_args != run_args or not self._run:
            self._run_args = run_args
            self._make_sim_run()

        if self._run_error:
            return [ ErroredPath(self._run_error, self._project, self.state.copy(), path=self) ]

        out = [ Path(self._project, s, path=self) for s in self._run.flat_successors ]
        if 'insn_bytes' in run_args and not 'addr' in run_args and len(out) == 1 \
                and isinstance(self._run, simuvex.SimIRSB) \
                and self.addr + self._run.irsb.size == out[0].state.se.any_int(out[0].state.regs.ip):
            out[0].state.regs.ip = self.addr
        return out

    def clear(self):
        '''
        This function clear the execution status.
        After calling this if you call step() successors will be recomputed.
        If you changed something into path state you probably want to call this method.
        '''
        self._run = None


    def _make_sim_run(self):
        self._run = None
        self._run_error = None
        try:
            self._run = self._project.factory.sim_run(self.state, **self._run_args)
        except (AngrError, simuvex.SimError, claripy.ClaripyError) as e:
            l.debug("Catching exception", exc_info=True)
            self._run_error = e
        except (TypeError, ValueError, ArithmeticError, MemoryError) as e:
            l.debug("Catching exception", exc_info=True)
            self._run_error = e

    @property
    def next_run(self):
        if self._run_error:
            return None
        if not self._run:
            raise AngrPathError("Please call path.step() before accessing next_run")
        return self._run

    @property
    def successors(self):
        if not (self._run_error or self._run):
            raise AngrPathError("Please call path.step() before accessing successors")
        return self.step(**self._run_args)

    @property
    def unconstrained_successors(self):
        if self._run_error:
            return []
        if not self._run:
            raise AngrPathError("Please call path.step() before accessing successors")
        return [ Path(self._project, s, path=self) for s in self._run.unconstrained_successors ]

    @property
    def unsat_successors(self):
        if self._run_error:
            return []
        if not self._run:
            raise AngrPathError("Please call path.step() before accessing successors")
        return [ Path(self._project, s, path=self) for s in self._run.unsat_successors ]

    @property
    def mp_successors(self):
        return mulpyplexer.MP(self.successors)

    @property
    def nonflat_successors(self):
        if self._run_error:
            return []
        if not self._run:
            raise AngrPathError("Please call path.step() before accessing successors")

        nonflat_successors = [ ]
        for s in self._run.successors + self._run.unconstrained_successors:
            sp = Path(self._project, s, path=self)
            nonflat_successors.append(sp)
        return nonflat_successors

    @property
    def unconstrained_successor_states(self):
        if self._run_error:
            return []
        if not self._run:
            raise AngrPathError("Please call path.step() before accessing successors")

        return self._run.unconstrained_successors

    #
    # Utility functions
    #

    def trim_history(self):
        '''
        Trims a path's history (removes actions, etc).
        '''

        #self.trace = self.trace[-1:]
        #self.addr_trace = self.addr_trace[-1:]
        #self.jumpkinds = self.jumpkinds[-1:]
        self.targets = self.targets[-1:]
        self.guards = self.guards[-1:]
        self.events = self.events[-1:]
        self.actions = self.actions[-1:]

    def divergence_addr(self, other):
        '''
        Returns the basic block at which the paths diverged.

        @param other: the other Path
        @returns an address (long)
        '''

        for i in range(max([len(self.addr_trace), len(other.addr_trace)])):
            if i > len(self.addr_trace):
                return other.addr_trace[i-1]
            elif i > len(other.addr_trace):
                return self.addr_trace[i-1]
            elif self.addr_trace[i] != other.addr_trace[i]:
                return self.addr_trace[i-1]


    def detect_loops(self, n=None): #pylint:disable=unused-argument
        '''
        Returns the current loop iteration that a path is on.

        @param n: the minimum number of iterations to check for.
        @returns the number of the loop iteration it's in
        '''

        # TODO: make this work better
        #addr_strs = [ "%x"%x for x in self.addr_trace ]
        #bigstr = "".join(addr_strs)

        #candidates = [ ]

        #max_iteration_length = len(self.addr_trace) / n
        #for i in range(max_iteration_length):
        #   candidates.append("".join(addr_strs[-i-0:]))

        #for c in reversed(candidates):
        #   if bigstr.count(c) >= n:
        #       return n
        #return None

        mc = self.callstack.top.block_counter.most_common()
        if len(mc) == 0:
            return None
        else:
            return mc[0][1]

    #
    # Error checking
    #

    _jk_errors = set(("Ijk_EmFail", "Ijk_NoDecode", "Ijk_MapFail"))
    _jk_signals = set(('Ijk_SigILL', 'Ijk_SigTRAP', 'Ijk_SigSEGV', 'Ijk_SigBUS',
                       'Ijk_SigFPE_IntDiv', 'Ijk_SigFPE_IntOvf'))
    _jk_all_bad = _jk_errors | _jk_signals

    #
    # Convenience functions
    #

    @property
    def reachable(self):
        return self._reachable if self._reachable is not None else self.state.satisfiable()

    @property
    def weighted_length(self):
        return self.length + self.extra_length

    @property
    def jumpkind(self):
        return self.state.scratch.jumpkind

    @property
    def _s0(self):
        return self.step()[0]
    @property
    def _s1(self):
        return self.step()[1]
    @property
    def _s2(self):
        return self.step()[2]
    @property
    def _s3(self):
        return self.step()[3]

    #
    # State continuation
    #

    def _record_state(self, state):
        '''
        Adds the information from the last run to the current path.
        '''

        if simuvex.o.TRACK_ACTION_HISTORY in state.options:
            self.events.extend(self.last_events)
            self.actions.extend(self.last_actions)

        self.jumpkinds.append(state.scratch.jumpkind)
        self.targets.append(state.scratch.target)
        self.guards.append(state.scratch.guard)

        # maintain the blockcounter stack
        if self.jumpkinds[-1] == "Ijk_Call":
            callframe = CallFrame(state)
            self.callstack.push(callframe)
            self.callstack_backtrace.append((hash(self.callstack), callframe, len(self.callstack)))
        elif self.jumpkinds[-1].startswith('Ijk_Sys'):
            callframe = CallFrame(state)
            self.callstack.push(callframe)
            self.callstack_backtrace.append((hash(self.callstack), callframe, len(self.callstack)))
        elif self.jumpkinds[-1] == "Ijk_Ret":
            self.popped_callframe = self.callstack.pop()
            if len(self.callstack) == 0:
                l.info("Path callstack unbalanced...")
                self.callstack.push(CallFrame(None, 0, 0, 0))

        self.addr_trace.append(state.scratch.bbl_addr)
        self.callstack.top.block_counter[state.scratch.bbl_addr] += 1

    def _record_run(self, run):
        self.trace.append(str(run))

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

        # fix the traces
        divergence_index = [ len(set(addrs)) == 1 for addrs in zip(*[ o.addr_trace for o in all_paths ]) ].index(False)
        new_path.addr_trace = self.addr_trace[:divergence_index]
        new_path.addr_trace.append(-1)
        new_path.trace = self.trace[:divergence_index]
        new_path.trace.append(("MERGE POINT: %s" % merge_flag))

        # reset the upcoming merge points
        new_path._upcoming_merge_points = [ ]
        new_path._merge_flags.append(merge_flag)
        new_path._merge_values.append(list(range(len(all_paths))))
        new_path._merge_traces.append( [ o.trace for o in all_paths ] )
        new_path._merge_addr_traces.append( [ o.addr_trace for o in all_paths ] )
        new_path._merge_depths.append(new_path.length) #

        return new_path

    def copy(self):
        p = Path(self._project, self.state.copy())

        p.last_events = list(self.last_events)
        p.last_actions = list(self.last_actions)
        p.events = list(self.events)
        p.actions = list(self.actions)

        p.trace = list(self.trace)
        p.addr_trace = list(self.addr_trace)
        p.callstack = self.callstack.copy()
        p.callstack_backtrace = list(self.callstack_backtrace)
        p.popped_callframe = self.popped_callframe

        p.guards = list(self.guards)
        p.jumpkinds = list(self.jumpkinds)
        p.targets = list(self.targets)

        p.length = self.length
        p.extra_length = self.extra_length
        p.previous_run = self.previous_run
        p._run = self._run

        p.info = {k: copy.copy(v) for k, v in self.info.iteritems()}

        p._upcoming_merge_points = list(self._upcoming_merge_points)
        p._merge_flags = list(self._merge_flags)
        p._merge_values = list(self._merge_values)
        p._merge_traces = list(self._merge_traces)
        p._merge_addr_traces = list(self._merge_addr_traces)
        p._merge_depths = list(self._merge_depths)

        return p

    def filter_actions(self, block_addr=None, block_stmt=None, insn_addr=None, read_from=None, write_to=None):
        '''
        Filter self.actions based on some common parameters.

        :param block_addr: Only return actions generated in blocks starting at this address.
        :param block_stmt: Only return actions generated in the nth statement of each block.
        :param insn_addr: Only return actions generated in the assembly instruction at this address.
        :param read_from: Only return actions that perform a read from the specified location.
        :param write_to: Only return actions that perform a write to the specified location.

        Notes:
        If IR optimization is turned on, reads and writes may not occur in the instruction
        they originally came from. Most commonly, If a register is read from twice in the same
        block, the second read will not happen, instead reusing the temp the value is already
        stored in.

        Valid values for read_from and write_to are the string literals 'reg' or 'mem' (matching
        any read or write to registers or memory, respectively), any string (representing a read
        or write to the named register), and any integer (representing a read or write to the
        memory at this address).
        '''
        if read_from is not None:
            if write_to is not None:
                raise ValueError("Can't handle read_from and write_to at the same time!")
            if read_from in ('reg', 'mem'):
                read_type = read_from
                read_offset = None
            elif isinstance(read_from, str):
                read_type = 'reg'
                read_offset = self._project.arch.registers[read_from][0]
            else:
                read_type = 'mem'
                read_offset = read_from
        if write_to is not None:
            if write_to in ('reg', 'mem'):
                write_type = write_to
                write_offset = None
            elif isinstance(write_to, str):
                write_type = 'reg'
                write_offset = self._project.arch.registers[write_to][0]
            else:
                write_type = 'mem'
                write_offset = write_to

        def addr_of_stmt(bbl_addr, stmt_idx):
            if stmt_idx is None:
                return None
            stmts = self._project.factory.block(bbl_addr).vex.statements
            if stmt_idx >= len(stmts):
                return None
            for i in reversed(xrange(stmt_idx + 1)):
                if stmts[i].tag == 'Ist_IMark':
                    return stmts[i].addr + stmts[i].delta
            return None

        def action_reads(action):
            if action.type != read_type:
                return False
            if action.action != 'read':
                return False
            if read_offset is None:
                return True
            addr = action.addr
            if isinstance(addr, simuvex.SimActionObject):
                addr = addr.ast
            if isinstance(addr, claripy.ast.Base):
                if addr.symbolic:
                    return False
                addr = self.state.se.any_int(addr)
            if addr != read_offset:
                return False
            return True

        def action_writes(action):
            if action.type != write_type:
                return False
            if action.action != 'write':
                return False
            if write_offset is None:
                return True
            addr = action.addr
            if isinstance(addr, simuvex.SimActionObject):
                addr = addr.ast
            if isinstance(addr, claripy.ast.Base):
                if addr.symbolic:
                    return False
                addr = self.state.se.any_int(addr)
            if addr != write_offset:
                return False
            return True

        return [x for x in self.actions if
                    (block_addr is None or x.bbl_addr == block_addr) and
                    (block_stmt is None or x.stmt_idx == block_stmt) and
                    (read_from is None or action_reads(x)) and
                    (write_to is None or action_writes(x)) and
                    (insn_addr is None or (x.sim_procedure is None and addr_of_stmt(x.bbl_addr, x.stmt_idx) == insn_addr))
            ]

    def __repr__(self):
        return "<Path with %d runs (at 0x%x)>" % (len(self.trace), self.addr)

class ErroredPath(Path):
    def __init__(self, error, *args, **kwargs):
        super(ErroredPath, self).__init__(*args, **kwargs)
        self.error = error
        self.errored = True

    def __repr__(self):
        return "<Errored Path with %d runs (at 0x%x, %s)>" % \
            (len(self.trace), self.addr, type(self.error).__name__)

    def step(self, *args, **kwargs):
        # pylint: disable=unused-argument
        raise AngrPathError("Cannot step forward an errored path")

    def retry(self, **kwargs):
        self._run_args = kwargs
        self._run = self._project.factory.sim_run(self.state, **self._run_args)
        return super(ErroredPath, self).step(**kwargs)

    def _record_state(self, *args, **kwargs):
        # pylint: disable=unused-argument
        pass

    def _record_run(self, *args, **kwargs):
        # pylint: disable=unused-argument
        pass


def make_path(project, runs):
    """
    A helper function to generate a correct angr.Path from a list of runs corresponding
    to a program path.

    We expect @runs to be a list of simruns corresponding to a program path
    """

    if len(runs) == 0:
        raise AngrPathError("Cannot generate Path from empty set of runs")

    # This creates a path which state is the the first run
    a_p = Path(project, runs[0].initial_state)
    # And records the first node's run
    a_p._record_run(runs[0])

    # We then go through all the nodes except the last one
    for r in runs[1:-1]:
        a_p._record_state(r.initial_state)
        a_p._record_run(r)

    # We record the last state and set it as current (it is the initial
    # state of the next run).
    a_p._record_state(runs[-1].initial_state)
    a_p.state = runs[-1].initial_state

    return a_p

from .errors import AngrError, AngrPathError
import simuvex
import claripy
