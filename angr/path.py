from os import urandom
import os
import copy
import sys
import logging
l = logging.getLogger("angr.path")

import mulpyplexer

from .errors import SimSolverModeError, SimUnsatError, SimError
from . import sim_options as o
from . import BP_BEFORE, BP_AFTER
from .sim_procedure import SimProcedure
from .call_stack import CallFrame, CallStack, CallStackAction
from .state_plugins.sim_action_object import SimActionObject

#pylint:disable=unidiomatic-typecheck

UNAVAILABLE_RET_ADDR = -1


class ReverseListProxy(list):
    def __iter__(self):
        return reversed(self)


class Path(object):
    """
    A Path represents a sequence of basic blocks for an execution of the program.

    :ivar name:              A string to identify the path.
    :ivar state:             The state of the program.
    :type state:             SimState
    :ivar strong_reference:  Whether or not to keep a strong reference to the previous state in path_history
    :
    """
    def __init__(self, project, state, path=None, strong_reference=False):
        # this is the state of the path
        self.state = state
        self.errored = False

        # project
        self._project = project

        if path is None:
            # the path history
            self.history = PathHistory()
            self.callstack = CallStack()
            self.callstack_backtrace = []

            # Note that stack pointer might be symbolic, and simply calling state.se.eval over sp will fail in that
            # case. We should catch exceptions here.
            try:
                stack_ptr = self.state.se.eval(self.state.regs.sp)
            except (SimSolverModeError, SimUnsatError, AttributeError):
                stack_ptr = None

            # generate a base callframe
            self._initialize_callstack(self.addr, stack_ptr)
            if o.REGION_MAPPING in self.state.options and o.ABSTRACT_MEMORY not in self.state.options:
                self._add_stack_region_mapping(self.state, sp=stack_ptr, ip=self.addr)

            self.popped_callframe = None

            # the previous run
            self.previous_run = None
            self.history._jumpkind = state.history.last_jumpkind

            # A custom information store that will be passed to all its descendents
            self.info = {}

            # for merging
            self._upcoming_merge_points = []

        else:
            # the path history
            self.history = PathHistory(path.history)
            self.callstack = path.callstack.copy()
            self.popped_callframe = path.popped_callframe
            self.callstack_backtrace = list(path.callstack_backtrace)

            # the previous run
            self.previous_run = path._run
            self.history._record_state(state, strong_reference)
            self.history._record_run(path._run)
            self._manage_callstack(state)

            # A custom information store that will be passed to all its descendents
            self.info = { k:copy.copy(v) for k, v in path.info.iteritems() }

            self._upcoming_merge_points = list(path._upcoming_merge_points)

        # for printing/ID stuff and inheritance
        self.name = str(id(self))
        self.path_id = urandom(8).encode('hex')

        # actual analysis stuff
        self._run_args = None       # successors args, to determine caching
        self._run = None
        self._run_error = None
        self._run_traceback = None

    @property
    def addr(self):
        return self.state.se.eval(self.state.regs.ip)

    @addr.setter
    def addr(self, val):
        self.state.regs.ip = val

    #
    # Pass-throughs to history
    #

    @property
    def length(self):
        return self.history.length

    @length.setter
    def length(self, v):
        l.warning("Manually setting length -- change this behavior.")
        self.history.length = v

    @property
    def extra_length(self):
        return self.history.extra_length

    @extra_length.setter
    def extra_length(self, val):
        self.history.extra_length = val

    @property
    def weighted_length(self):
        return self.history.length + self.history.extra_length

    @property
    def jumpkind(self):
        return self.history._jumpkind

    @property
    def recent_actions(self):
        return self.history.actions

    #
    # History traversal
    #

    @property
    def history_iterator(self):
        return HistoryIter(self.history)
    @property
    def addr_trace(self):
        return AddrIter(self.history)
    @property
    def trace(self):
        return RunstrIter(self.history)
    @property
    def targets(self):
        return TargetIter(self.history)
    @property
    def guards(self):
        return GuardIter(self.history)
    @property
    def jumpkinds(self):
        return JumpkindIter(self.history)
    @property
    def events(self):
        return EventIter(self.history)
    @property
    def actions(self):
        return ActionIter(self.history)

    def trim_history(self):
        self.history = self.history.copy()
        self.history._parent = None


    #
    # Stepping methods and successor access
    #

    def step(self, throw=None, **run_args):
        """
        Step a path forward. Optionally takes any argument applicable to project.factory.successors.

        :param jumpkind:          the jumpkind of the previous exit.
        :param addr address:      to execute at instead of the state's ip.
        :param whitelist:         a list of stmt indexes to which to confine execution.
        :param last_stmt:         a statement index at which to stop execution.
        :param thumb:             whether the block should be lifted in ARM's THUMB mode.
        :param backup_state:      a state to read bytes from instead of using project memory.
        :param opt_level:         the VEX optimization level to use.
        :param insn_bytes:        a string of bytes to use for the block instead of #the project.
        :param size:              the maximum size of the block, in bytes.
        :param num_inst:          the maximum number of instructions.
        :param traceflags:        traceflags to be passed to VEX. Default: 0
        :param strong_reference   whether or not to keep a strong reference to the previous state. Default: False

        :returns:   An array of paths for the possible successors.
        """

        # backward compatibility
        if 'max_size' in run_args:
            l.warning('"max_size" has been deprecated in Path.step(). Please use "size" instead.')
            size = run_args.pop('max_size')
            run_args['size'] = size

        if self._run_args != run_args or not self._run:
            self._run_args = run_args
            self._make_successors(throw=throw)

        self.state._inspect('path_step', BP_BEFORE)

        if self._run_error:
            return [ self.copy(error=self._run_error, traceback=self._run_traceback) ]

        strong_reference = run_args.get("strong_reference", False)
        out = [Path(self._project, s, path=self, strong_reference=strong_reference) for s in self._run.flat_successors]
        if 'insn_bytes' in run_args and 'addr' not in run_args and len(out) == 1 \
                and isinstance(self._run, simuvex.SimIRSB) \
                and self.addr + self._run.irsb.size == out[0].state.se.eval(out[0].state.regs.ip):
            out[0].state.regs.ip = self.addr

        for p in out:
            p.state._inspect('path_step', BP_AFTER)
        return out

    def clear(self):
        """
        This function clear the execution status.

        After calling this if you call :func:`step`, successors will be recomputed. If you changed something into path
        state you probably want to call this method.
        """
        self._run = None


    def _make_successors(self, throw=None):
        self._run = None
        self._run_error = None
        self._run_traceback = None
        try:
            self._run = self._project.factory.successors(self.state, **self._run_args)
        except (AngrError, SimError, claripy.ClaripyError) as e:
            l.debug("Catching exception", exc_info=True)
            self._run_error = e
            self._run_traceback = sys.exc_info()[2]
            if throw:
                raise
        except (TypeError, ValueError, ArithmeticError, MemoryError) as e:
            l.debug("Catching exception", exc_info=True)
            self._run_error = e
            self._run_traceback = sys.exc_info()[2]
            if throw:
                raise

    @property
    def next_run(self):
        # TODO: this should be documented.
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

    def branch_causes(self):
        """
        Returns the variables that have caused this path to branch.

        :return: A list of tuples of (basic block address, jmp instruction address, set(variables))
        """
        return [
            (h.addr, h._jump_source, tuple(h._guard.variables)) for h in self.history_iterator
            if h._jump_avoidable
        ]

    def divergence_addr(self, other):
        """
        Returns the basic block at which the paths diverged.

        :param other: The other Path.
        :returns:     The address of the basic block.
        """

        trace1 = self.addr_trace.hardcopy
        trace2 = other.addr_trace.hardcopy
        for i in range(max([len(trace1), len(trace2)])):
            if i > len(trace1):
                return trace2[i-1]
            elif i > len(trace2):
                return trace1[i-1]
            elif trace1[i] != trace2[i]:
                return trace1[i-1]


    def detect_loops(self, n=None): #pylint:disable=unused-argument
        """
        Returns the current loop iteration that a path is on.

        :param n:   The minimum number of iterations to check for.
        :returns:   The number of the loop iteration it's in.
        """

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
        return self.history.reachable()

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

    def _manage_callstack(self, state):
        """
        Adds the information from the last run to the current path.
        """

        # maintain the blockcounter stack
        if state.scratch.bbl_addr_list is not None:
            # there are more than one block - probably from Unicorn engine

            block_addr_to_jumpkind = { } # cache

            for i, bbl_addr in enumerate(state.scratch.bbl_addr_list):

                try:
                    block_size, jumpkind = block_addr_to_jumpkind[bbl_addr]
                except KeyError:
                    if self._project.is_hooked(bbl_addr):
                        # hooked by a SimProcedure or a user hook
                        if issubclass(self._project.hooked_by(bbl_addr), SimProcedure):
                            block_size = None  # it will not be used
                            jumpkind = 'Ijk_Ret'
                        else:
                            block_size = None  # will not be used either
                            jumpkind = 'Ijk_Boring'

                    elif self._project.simos.is_syscall_addr(bbl_addr):
                        # it's a syscall
                        block_size = None
                        jumpkind = 'Ijk_Ret'

                    else:
                        block = self._project.factory.block(bbl_addr, backup_state=state)
                        block_size = block.size
                        jumpkind = block.vex.jumpkind

                    block_addr_to_jumpkind[bbl_addr] = block_size, jumpkind

                if jumpkind == 'Ijk_Call':
                    if i == len(state.scratch.bbl_addr_list) - 1:
                        call_site_addr = state.scratch.bbl_addr_list[i - 1] if i > 0 else None
                        self._manage_callstack_call(state=state, call_site_addr=call_site_addr)
                        if o.REGION_MAPPING in self.state.options and o.ABSTRACT_MEMORY not in self.state.options:
                            self._add_stack_region_mapping(state)
                    else:
                        call_site_addr = state.scratch.bbl_addr_list[i]
                        func_addr = state.scratch.bbl_addr_list[i + 1]
                        stack_ptr = state.scratch.stack_pointer_list[i + 1]
                        ret_addr = bbl_addr + block_size
                        self._manage_callstack_call(call_site_addr=call_site_addr, func_addr=func_addr,
                                                    stack_ptr=stack_ptr, ret_addr=ret_addr
                                                    )
                        if o.REGION_MAPPING in self.state.options and o.ABSTRACT_MEMORY not in self.state.options:
                            self._add_stack_region_mapping(state, sp=stack_ptr, ip=func_addr)

                elif jumpkind.startswith('Ijk_Sys'):
                    if i == len(state.scratch.bbl_addr_list) - 1:
                        call_site_addr = state.scratch.bbl_addr_list[i - 1] if i > 0 else None
                        self._manage_callstack_sys(state=state, call_site_addr=call_site_addr)
                        if o.REGION_MAPPING in self.state.options and o.ABSTRACT_MEMORY not in self.state.options:
                            self._add_stack_region_mapping(state)
                    else:
                        call_site_addr = state.scratch.bbl_addr_list[i]
                        func_addr = state.scratch.bbl_addr_list[i + 1]
                        stack_ptr = state.scratch.stack_pointer_list[i + 1]
                        ret_addr = bbl_addr + block_size
                        self._manage_callstack_sys(call_site_addr=call_site_addr, func_addr=func_addr,
                                                   stack_ptr=stack_ptr, ret_addr=ret_addr, jumpkind=jumpkind
                                                   )
                        if o.REGION_MAPPING in self.state.options and o.ABSTRACT_MEMORY not in self.state.options:
                            self._add_stack_region_mapping(state, sp=stack_ptr, ip=func_addr)

                elif jumpkind == 'Ijk_Ret':
                    if i == len(state.scratch.bbl_addr_list) - 1:
                        ret_site_addr = state.scratch.bbl_addr_list[i - 1] if i > 0 else None
                    else:
                        ret_site_addr = state.scratch.bbl_addr_list[i]
                    self._manage_callstack_ret(ret_site_addr)

        else:
            # there is only one block
            call_site_addr = self.previous_run.addr if self.previous_run else None
            if state.history.last_jumpkind == "Ijk_Call":
                self._manage_callstack_call(state=state, call_site_addr=call_site_addr)
                if o.REGION_MAPPING in self.state.options and o.ABSTRACT_MEMORY not in self.state.options:
                    self._add_stack_region_mapping(state)

            elif state.history.last_jumpkind.startswith('Ijk_Sys'):
                self._manage_callstack_sys(state=state, call_site_addr=call_site_addr)
                if o.REGION_MAPPING in self.state.options and o.ABSTRACT_MEMORY not in self.state.options:
                    self._add_stack_region_mapping(state)

            elif state.history.last_jumpkind == "Ijk_Ret":
                ret_site_addr = call_site_addr
                self._manage_callstack_ret(ret_site_addr)

            self.callstack.top.block_counter[state.scratch.bbl_addr] += 1

    def _initialize_callstack(self, addr, stack_ptr):
        callframe = CallFrame(call_site_addr=None, func_addr=addr, stack_ptr=stack_ptr, ret_addr=UNAVAILABLE_RET_ADDR,
                              jumpkind='Ijk_Boring'
                              )
        self.callstack.push(callframe)
        self.callstack_backtrace.append(CallStackAction(hash(self.callstack), len(self.callstack), 'push',
                                                        callframe=callframe
                                                        )
                                        )

    def _manage_callstack_call(self, state=None, call_site_addr=None, func_addr=None, stack_ptr=None, ret_addr=None):
        if state is not None:
            callframe = CallFrame(state=state, call_site_addr=call_site_addr)
        else:
            callframe = CallFrame(call_site_addr=call_site_addr, func_addr=func_addr, stack_ptr=stack_ptr, ret_addr=ret_addr, jumpkind='Ijk_Call')

        self.callstack.push(callframe)
        self.callstack_backtrace.append(CallStackAction(hash(self.callstack), len(self.callstack), 'push',
                                                        callframe=callframe
                                                        )
                                        )

    def _manage_callstack_sys(self, state=None, call_site_addr=None, func_addr=None, stack_ptr=None, ret_addr=None, jumpkind=None):
        if state is not None:
            callframe = CallFrame(state=state, call_site_addr=call_site_addr)
        else:
            callframe = CallFrame(call_site_addr=call_site_addr, func_addr=func_addr, stack_ptr=stack_ptr, ret_addr=ret_addr, jumpkind=jumpkind)

        self.callstack.push(callframe)
        self.callstack_backtrace.append(CallStackAction(hash(self.callstack), len(self.callstack), 'push',
                                                        callframe=callframe
                                                        )
                                        )

    def _manage_callstack_ret(self, ret_site_addr):
        if len(self.callstack) != 0:
            self.popped_callframe = self.callstack.pop()
            self.callstack_backtrace.append(CallStackAction(hash(self.callstack), len(self.callstack), 'pop',
                                                            ret_site_addr=ret_site_addr
                                                            )
                                            )

        if len(self.callstack) == 0:
            l.info("Callstack on the path is unbalanced.")

            # make sure there is at least one dummy callframe available
            self.callstack.push(CallFrame(state=None, func_addr=0, stack_ptr=0, ret_addr=0))

    #
    # Region mapping
    #

    def _add_stack_region_mapping(self, state, sp=None, ip=None):
        if sp is None or ip is None:
            # dump sp and ip from state
            if state.regs.sp.symbolic:
                l.warning('Got a symbolic stack pointer. Stack region mapping may break.')
                sp = state.se.max(state.regs.sp)
            else:
                sp = state.regs.sp._model_concrete.value

            # ip cannot be symbolic
            ip = state.regs.ip._model_concrete.value

        region_id = self.state.memory.stack_id(ip)
        self.state.memory.set_stack_address_mapping(sp, region_id, ip)

    #
    # Merging and splitting
    #

    def merge(self, other_paths, common_history):
        """
        Returns a merger of this path with all the paths in other_paths.

        :param other_paths: list of paths to merge together with self
        :param common_history: a PathHistory node shared by all the paths. Must be provided; causes
                               merging to be more efficient, and actions and such are merged.
        :returns: the merged Path
        :rtype: Path
        """

        all_paths = other_paths + [self]
        if len(set(( o.addr for o in all_paths))) != 1:
            raise AngrPathError("Unable to merge paths.")

        # get the different constraints
        constraints = [ p.history.constraints_since(common_history) for p in all_paths ]

        # merge the state with these constraints
        new_state, merge_conditions, _ = all_paths[0].state.merge(
            *[ p.state for p in all_paths[1:] ], merge_conditions=constraints,
            common_ancestor=common_history.state
        )
        new_path = Path(all_paths[0]._project, new_state, path=all_paths[0])

        # fix up the new path
        new_path.history = PathHistory(common_history)
        new_path.history.merged_from.extend(p.history for p in all_paths)
        new_path.history.merge_conditions = merge_conditions
        new_path.history._record_state(new_state)
        new_path.history._runstr = "MERGE POINT (at %#x)" % new_path.addr
        new_path.history.length -= 1

        # reset the upcoming merge points
        new_path._upcoming_merge_points = []

        # and return
        return new_path

    def copy(self, error=None, traceback=None):
        if error is None:
            p = Path(self._project, self.state.copy())
        else:
            p = ErroredPath(error, traceback, self._project, self.state.copy())

        p.history = self.history.copy()
        p.callstack = self.callstack.copy()
        p.callstack_backtrace = list(self.callstack_backtrace)
        p.popped_callframe = self.popped_callframe


        p.previous_run = self.previous_run
        p._run = self._run

        p.info = {k: copy.copy(v) for k, v in self.info.iteritems()}

        p._upcoming_merge_points = list(self._upcoming_merge_points)
        return p

    def filter_actions(self, block_addr=None, block_stmt=None, insn_addr=None, read_from=None, write_to=None):
        """
        Filter self.actions based on some common parameters.

        :param block_addr:  Only return actions generated in blocks starting at this address.
        :param block_stmt:  Only return actions generated in the nth statement of each block.
        :param insn_addr:   Only return actions generated in the assembly instruction at this address.
        :param read_from:   Only return actions that perform a read from the specified location.
        :param write_to:    Only return actions that perform a write to the specified location.

        Notes:
        If IR optimization is turned on, reads and writes may not occur in the instruction
        they originally came from. Most commonly, If a register is read from twice in the same
        block, the second read will not happen, instead reusing the temp the value is already
        stored in.

        Valid values for read_from and write_to are the string literals 'reg' or 'mem' (matching
        any read or write to registers or memory, respectively), any string (representing a read
        or write to the named register), and any integer (representing a read or write to the
        memory at this address).
        """
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
            if isinstance(addr, SimActionObject):
                addr = addr.ast
            if isinstance(addr, claripy.ast.Base):
                if addr.symbolic:
                    return False
                addr = self.state.se.eval(addr)
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
            if isinstance(addr, SimActionObject):
                addr = addr.ast
            if isinstance(addr, claripy.ast.Base):
                if addr.symbolic:
                    return False
                addr = self.state.se.eval(addr)
            if addr != write_offset:
                return False
            return True

        return [x for x in reversed(self.actions) if
                    (block_addr is None or x.bbl_addr == block_addr) and
                    (block_stmt is None or x.stmt_idx == block_stmt) and
                    (read_from is None or action_reads(x)) and
                    (write_to is None or action_writes(x)) and
                    (insn_addr is None or (x.sim_procedure is None and addr_of_stmt(x.bbl_addr, x.stmt_idx) == insn_addr))
            ]

    def __repr__(self):
        where_object = self._project.loader.find_object_containing(self.addr)
        if where_object is None:
            return "<Path with %d runs (at 0x%x)>" % (self.length, self.addr)
        else:
            return "<Path with %d runs (at 0x%x : %s)>" % (self.length,
                                                           self.addr,
                                                           os.path.basename(where_object.binary)
                                                           )


class ErroredPath(Path):
    """
    ErroredPath is used for paths that have encountered and error in their symbolic execution. This kind of path cannot
    be stepped further.

    :ivar error:    The error that was encountered.
    """
    def __init__(self, error, traceback, *args, **kwargs):
        super(ErroredPath, self).__init__(*args, **kwargs)
        self.error = error
        self.traceback = traceback
        self.errored = True

    def __repr__(self):
        return "<Errored Path with %d runs (at 0x%x, %s)>" % \
            (self.length, self.addr, type(self.error).__name__)

    def step(self, *args, **kwargs):
        # pylint: disable=unused-argument
        raise AngrPathError("Cannot step forward an errored path")

    def retry(self, **kwargs):
        self._run_args = kwargs
        self._run = self._project.factory.successors(self.state, **self._run_args)
        return super(ErroredPath, self).step(**kwargs)

    def debug(self):
        import ipdb
        ipdb.post_mortem(self.traceback)


from .errors import AngrError, AngrPathError
from .path_history import * #pylint:disable=wildcard-import,unused-wildcard-import
