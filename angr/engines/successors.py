import claripy

import logging
l = logging.getLogger("angr.engines.successors")

class SimSuccessors(object):
    """
    This class serves as a categorization of all the kinds of result states that can come from a
    SimEngine run.

    :ivar int addr:         The address at which execution is taking place, as a python int
    :ivar initial_state:    The initial state for which execution produced these successors
    :ivar engine:           The engine that produced these successors
    :ivar sort:             A string identifying the type of engine that produced these successors
    :ivar bool processed:   Whether or not the processing succeeded
    :ivar str description:  A textual description of the execution step

    The successor states produced by this run are categorized into several lists:

    :ivar dict artifacts:   Any analysis byproducts (for example, an IRSB) that were produced during execution
    :ivar successors:       The "normal" successors. IP may be symbolic, but must have reasonable number of solutions
    :ivar unsat_successors: Any successor which is unsatisfiable after its guard condition is added.
    :ivar all_successors:   successors + unsat_successors
    :ivar flat_successors:  The normal successors, but any symbolic IPs have been concretized. There is one state in
                            this list for each possible value an IP may be concretized to for each successor state.
    :ivar unconstrained_successors:
                            Any state for which during the flattening process we find too many solutions.

    A more detailed description of the successor lists may be found here: https://docs.angr.io/docs/simuvex.html
    """

    def __init__(self, addr, initial_state):
        self.addr = addr
        self.initial_state = initial_state

        self.successors = [ ]
        self.all_successors = [ ]
        self.flat_successors = [ ]
        self.unsat_successors = [ ]
        self.unconstrained_successors = [ ]

        # the engine that should process or did process this request
        self.engine = None
        self.processed = False
        self.description = 'SimSuccessors'
        self.sort = None
        self.artifacts = {}

    @classmethod
    def failure(cls):
        return cls(None, None)

    def __repr__(self):
        if self.processed:
            successor_strings = [ ]
            if len(self.flat_successors) != 0:
                successor_strings.append("%d sat" % len(self.flat_successors))
            if len(self.unsat_successors) != 0:
                successor_strings.append("%d unsat" % len(self.unsat_successors))
            if len(self.unconstrained_successors) != 0:
                successor_strings.append("%d unconstrained" % len(self.unconstrained_successors))

            if len(successor_strings) == 0:
                result = 'empty'
            else:
                result = ' '.join(successor_strings)
        else:
            result = 'failure'

        return '<%s from %#x: %s>' % (self.description, self.addr, result)

    @property
    def is_empty(self):
        return not self.all_successors and not self.flat_successors and not self.unsat_successors and \
               not self.unconstrained_successors

    def __getitem__(self, k):
        return self.flat_successors[k]

    def __iter__(self):
        return iter(self.flat_successors)

    def add_successor(self, state, target, guard, jumpkind, add_guard=True, exit_stmt_idx=None, exit_ins_addr=None,
                      source=None):
        """
        Add a successor state of the SimRun.
        This procedure stores method parameters into state.scratch, does some housekeeping,
        and calls out to helper functions to prepare the state and categorize it into the appropriate
        successor lists.

        :param SimState state:    The successor state.
        :param target:            The target (of the jump/call/ret).
        :param guard:             The guard expression.
        :param str jumpkind:      The jumpkind (call, ret, jump, or whatnot).
        :param bool add_guard:    Whether to add the guard constraint (default: True).
        :param int exit_stmt_idx: The ID of the exit statement, an integer by default. 'default'
                                  stands for the default exit, and None means it's not from a
                                  statement (for example, from a SimProcedure).
        :param int exit_ins_addr: The instruction pointer of this exit, which is an integer by default.
        :param int source:        The source of the jump (i.e., the address of the basic block).
        """

        # First, trigger the SimInspect breakpoint
        state._inspect('exit', BP_BEFORE, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)
        state.scratch.target = state._inspect_getattr("exit_target", target)
        state.scratch.guard = state._inspect_getattr("exit_guard", guard)
        state.history.jumpkind = state._inspect_getattr("exit_jumpkind", jumpkind)
        state.history.jump_target = state.scratch.target
        state.history.jump_guard = state.scratch.guard

        # track some vex-specific stuff here for now
        state.scratch.source = source if source is not None else self.addr
        state.scratch.exit_stmt_idx = exit_stmt_idx
        state.scratch.exit_ins_addr = exit_ins_addr

        self._preprocess_successor(state, add_guard=add_guard)
        self._categorize_successor(state)
        state._inspect('exit', BP_AFTER, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)
        state.inspect.downsize()

    #
    # Successor management
    #

    def _preprocess_successor(self, state, add_guard=True): #pylint:disable=unused-argument
        """
        Preprocesses the successor state.

        :param state: the successor state
        """

        # Next, simplify what needs to be simplified
        if o.SIMPLIFY_EXIT_STATE in state.options:
            state.se.simplify()
        if o.SIMPLIFY_EXIT_GUARD in state.options:
            state.scratch.guard = state.se.simplify(state.scratch.guard)
        if o.SIMPLIFY_EXIT_TARGET in state.options:
            state.scratch.target = state.se.simplify(state.scratch.target)

        # unwrap stuff from SimActionObjects
        state.scratch.target = _raw_ast(state.scratch.target)
        state.scratch.guard = _raw_ast(state.scratch.guard)

        # apply the guard constraint and new program counter to the state
        if add_guard:
            state.add_constraints(state.scratch.guard)
        # trigger inspect breakpoints here since this statement technically shows up in the IRSB as the "next"
        state.regs.ip = state.scratch.target

        # For architectures with no stack pointer, we can't manage a callstack. This has the side effect of breaking
        # SimProcedures that call out to binary code self.call.
        if self.initial_state.arch.sp_offset is not None:
            self._manage_callstack(state)

        if len(self.successors) != 0:
            # This is a fork!
            state._inspect('fork', BP_AFTER)

        # clean up the state
        state.options.discard(o.AST_DEPS)
        state.options.discard(o.AUTO_REFS)

    @staticmethod
    def _manage_callstack(state):
        # condition for call = Ijk_Call
        # condition for ret = stack pointer drops below call point
        if state.history.jumpkind == 'Ijk_Call':
            state._inspect('call', BP_BEFORE, function_address=state.regs._ip)
            new_func_addr = state._inspect_getattr('function_address', None)
            if new_func_addr is not None and not claripy.is_true(new_func_addr == state.regs._ip):
                state.regs._ip = new_func_addr

            if state.arch.call_pushes_ret:
                ret_addr = state.mem[state.regs._sp].long.concrete
            else:
                ret_addr = state.se.eval(state.regs._lr)
            try:
                state_addr = state.addr
            except SimValueError:
                state_addr = None
            new_frame = CallStack(
                    call_site_addr=state.history.recent_bbl_addrs[-1],
                    func_addr=state_addr,
                    stack_ptr=state.se.eval(state.regs._sp),
                    ret_addr=ret_addr,
                    jumpkind='Ijk_Call')
            state.callstack.push(new_frame)

            state._inspect('call', BP_AFTER)
        else:
            while state.se.is_true(state.regs._sp > state.callstack.top.stack_ptr):
                state._inspect('return', BP_BEFORE, function_address=state.callstack.top.func_addr)
                state.callstack.pop()
                state._inspect('return', BP_AFTER)

            if not state.arch.call_pushes_ret and \
                    claripy.is_true(state.regs._ip == state.callstack.ret_addr) and \
                    claripy.is_true(state.regs._sp == state.callstack.stack_ptr):
                # very weird edge case that's not actually weird or on the edge at all:
                # if we use a link register for the return address, the stack pointer will be the same
                # before and after the call. therefore we have to check for equality with the marker
                # along with this other check with the instruction pointer to guess whether it's time
                # to pop a callframe. Still better than relying on Ijk_Ret.
                state._inspect('return', BP_BEFORE, function_address=state.callstack.top.func_addr)
                state.callstack.pop()
                state._inspect('return', BP_AFTER)


    def _categorize_successor(self, state):
        """
        Append state into successor lists.

        :param state: a SimState instance
        :param target: The target (of the jump/call/ret)
        :return: The state
        """

        self.all_successors.append(state)
        target = state.scratch.target

        # categorize the state
        if o.APPROXIMATE_GUARDS in state.options and state.se.is_false(state.scratch.guard, exact=False):
            if o.VALIDATE_APPROXIMATIONS in state.options:
                if state.satisfiable():
                    raise Exception('WTF')
            self.unsat_successors.append(state)
        elif o.APPROXIMATE_SATISFIABILITY in state.options and not state.se.satisfiable(exact=False):
            if o.VALIDATE_APPROXIMATIONS in state.options:
                if state.se.satisfiable():
                    raise Exception('WTF')
            self.unsat_successors.append(state)
        elif not state.scratch.guard.symbolic and state.se.is_false(state.scratch.guard):
            self.unsat_successors.append(state)
        elif o.LAZY_SOLVES not in state.options and not state.satisfiable():
            self.unsat_successors.append(state)
        elif o.NO_SYMBOLIC_JUMP_RESOLUTION in state.options and state.se.symbolic(target):
            self.unconstrained_successors.append(state)
        elif not state.se.symbolic(target) and not state.history.jumpkind.startswith("Ijk_Sys"):
            # a successor with a concrete IP, and it's not a syscall
            self.successors.append(state)
            self.flat_successors.append(state)
        elif state.history.jumpkind.startswith("Ijk_Sys"):
            # syscall
            self.successors.append(state)

            # Misuse the ip_at_syscall register to save the return address for this syscall
            # state.ip *might be* changed to be the real address of syscall SimProcedures by syscall handling code in
            # angr
            state.regs.ip_at_syscall = state.ip

            try:
                symbolic_syscall_num, concrete_syscall_nums = self._resolve_syscall(state)
                if concrete_syscall_nums is not None:
                    for n in concrete_syscall_nums:
                        split_state = state.copy()
                        split_state.add_constraints(symbolic_syscall_num == n)
                        split_state.inspect.downsize()
                        self._fix_syscall_ip(split_state)

                        self.flat_successors.append(split_state)
                else:
                    # We cannot resolve the syscall number
                    # However, we still put it to the flat_successors list, and angr.SimOS.handle_syscall will pick it
                    # up, and create a "unknown syscall" stub for it.
                    self._fix_syscall_ip(state)
                    self.flat_successors.append(state)
            except AngrUnsupportedSyscallError:
                self.unsat_successors.append(state)

        else:
            # a successor with a symbolic IP
            try:
                if o.KEEP_IP_SYMBOLIC in state.options:
                    s = claripy.Solver()
                    addrs = s.eval(target, 257, extra_constraints=tuple(state.ip_constraints))
                    if len(addrs) > 256:
                        # It is not a library
                        l.debug("It is not a Library")
                        addrs = state.se.eval_upto(target, 257)
                        if len(addrs) == 1:
                            state.add_constraints(target == addrs[0])
                        l.debug("addrs :%s", addrs)
                else:
                    addrs = state.se.eval_upto(target, 257)

                if len(addrs) > 256:
                    l.warning(
                        "Exit state has over 257 possible solutions. Likely unconstrained; skipping. %s",
                        target.shallow_repr()
                    )
                    self.unconstrained_successors.append(state)
                else:
                    for a in addrs:
                        split_state = state.copy()
                        if o.KEEP_IP_SYMBOLIC in split_state.options:
                            split_state.regs.ip = target
                        else:
                            split_state.add_constraints(target == a, action=True)
                            split_state.regs.ip = a
                        split_state.inspect.downsize()
                        self.flat_successors.append(split_state)
                    self.successors.append(state)
            except SimSolverModeError:
                self.unsat_successors.append(state)

        return state


    # misc stuff
    @staticmethod
    def _resolve_syscall(state):
        if state.os_name in SYSCALL_CC[state.arch.name]:
            cc = SYSCALL_CC[state.arch.name][state.os_name](state.arch)
        else:
            # Use the default syscall calling convention - it may bring problems
            cc = SYSCALL_CC[state.arch.name]['default'](state.arch)

        syscall_num = cc.syscall_num(state)

        if syscall_num.symbolic and o.NO_SYMBOLIC_SYSCALL_RESOLUTION in state.options:
            l.debug("Not resolving symbolic syscall number")
            return syscall_num, None
        maximum = state.posix.maximum_symbolic_syscalls
        possible = state.se.eval_upto(syscall_num, maximum + 1)

        if len(possible) == 0:
            raise AngrUnsupportedSyscallError("Unsatisfiable state attempting to do a syscall")

        if len(possible) > maximum:
            l.warning("Too many possible syscalls. Concretizing to 1.")
            possible = possible[:1]

        l.debug("Possible syscall values: %s", possible)

        return syscall_num, possible

    @staticmethod
    def _fix_syscall_ip(state):
        """
        Resolve syscall information from the state, get the IP address of the syscall SimProcedure, and set the IP of
        the state accordingly. Don't do anything if the resolution fails.

        :param SimState state: the program state.
        :return: None
        """

        try:
            bypass = o.BYPASS_UNSUPPORTED_SYSCALL in state.options
            stub = state.project.simos.syscall(state, allow_unsupported=bypass)
            if stub: # can be None if simos is not a subclass of SimUserspace
                state.ip = stub.addr # fix the IP
        except AngrUnsupportedSyscallError:
            pass # the syscall is not supported. don't do anything

    def _finalize(self):
        """
        Finalizes the request.
        """
        if len(self.all_successors) == 0:
            return

        # do some cleanup
        if o.DOWNSIZE_Z3 in self.all_successors[0].options:
            for s in self.all_successors:
                s.downsize()

        # record if the exit is unavoidable
        if len(self.flat_successors) == 1 and len(self.unconstrained_successors) == 0:
            self.flat_successors[0].scratch.avoidable = False


from ..state_plugins.inspect import BP_BEFORE, BP_AFTER
from ..errors import SimSolverModeError, AngrUnsupportedSyscallError, SimValueError
from ..calling_conventions import SYSCALL_CC
from ..state_plugins.sim_action_object import _raw_ast
from ..state_plugins.callstack import CallStack
from .. import sim_options as o
