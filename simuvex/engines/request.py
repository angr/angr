import claripy
import contextlib

import logging
l = logging.getLogger('simuvex.engine.request')

class SimEngineRequest(object):
    """
    This class serves as a container for the input to SimEngine and output from a SimEngine.
    """

    def __init__(self, state, inline=False, force_bbl_addr=None, *args, **kwargs):
        """
        Create a SimEngineRequest.
        """
        self.kwargs = kwargs
        self.args = args
        self.input_state = state
        self.active_state = None

        # whether or not the execution should be "inlined"
        self.inline = inline

        # an override for the address of the state
        self.force_bbl_addr = force_bbl_addr

        # The successors of this SimRun
        self.successors = [ ]
        self.all_successors = [ ]
        self.flat_successors = [ ]
        self.unsat_successors = [ ]
        self.unconstrained_successors = [ ]

        # the engine that should process or did process this request
        self.engine = None
        self.processed = False

        # the name (for stringification)
        self.custom_name = None

        # some scratch stuff for the VEX engine
        self.irsb = None
        self.conditional_guards = None
        self.last_imark = None

        # some scratch stuff for the SimProcedure engine
        self.procedure = None
        self.sim_kwargs = None
        self.ret_to = None
        self.ret_expr = None

    @property
    def addr(self):
        if self.force_bbl_addr is not None:
            return self.input_state.any_int(self.input_state.pc)
        else:
            return self.force_bbl_addr

    def __repr__(self):
        start_str = "%s to %s" % (self.input_state.scratch.jumpkind, self.addr)

        if self.processed:
            successor_strings = [ ]
            if len(self.flat_successors) != 0:
                successor_strings.append("%d sat")
            if len(self.unsat_successors) != 0:
                successor_strings.append("%d unsat")
            if len(self.unconstrained_successors) != 0:
                successor_strings.append("%d unconstrained")

            if len(successor_strings) != 0:
                successors = "successors (%s)" % ", ".join(successor_strings)

            processed_str = " - ".join((successors, self.engine.describe(self)))
        else:
            processed_str = "unprocessed"

        return "<SimEngineRequest %s - %s>" % (start_str, processed_str)

    def add_successor(self, state, target, guard, jumpkind, add_guard=True, exit_stmt_idx=None, source=None):
        """
        Add a successor state of the SimRun.
        This procedure stores method parameters into state.scratch, does some housekeeping,
        and calls out to helper functions to prepare the state and categorize it into the appropriate
        successor lists.

        :param state:          The successor state.
        :param target:          The target (of the jump/call/ret).
        :param guard:          The guard expression.
        :param jumpkind:      The jumpkind (call, ret, jump, or whatnot).
        :param add_guard:     Whether to add the guard constraint (default: True).
        :param exit_stmt_idx: The ID of the exit statement, an integer by default. 'default'
                              stands for the default exit, and None means it's not from a
                              statement (for example, from a SimProcedure).
        :param source:          The source of the jump (i.e., the address of the basic block).
        """

        # First, trigger the SimInspect breakpoint
        state._inspect('exit', BP_BEFORE, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)
        state.scratch.target = state._inspect_getattr("exit_target", target)
        state.scratch.guard = state._inspect_getattr("exit_guard", guard)
        state.scratch.jumpkind = state._inspect_getattr("exit_jumpkind", jumpkind)

        # track some vex-specific stuff here for now
        state.scratch.source = source if source is not None else self.addr
        state.scratch.exit_stmt_idx = exit_stmt_idx

        self._preprocess_successor(state, add_guard=add_guard)
        self._categorize_successor(state)
        state._inspect('exit', BP_AFTER, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)

    #
    # Successor management
    #

    @staticmethod
    def _preprocess_successor(state, add_guard=True): #pylint:disable=unused-argument
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
        state.regs.ip = state.scratch.target

        # clean up the state
        state.options.discard(o.AST_DEPS)
        state.options.discard(o.AUTO_REFS)

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
        elif not state.se.symbolic(target) and not state.scratch.jumpkind.startswith("Ijk_Sys"):
            # a successor with a concrete IP, and it's not a syscall
            self.successors.append(state)
            self.flat_successors.append(state)
        elif state.scratch.jumpkind.startswith("Ijk_Sys"):
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

                        self.flat_successors.append(split_state)
                else:
                    # We cannot resolve the syscall number
                    # However, we still put it to the flat_successors list, and angr.SimOS.handle_syscall will pick it
                    # up, and create a "unknown syscall" stub for it.
                    self.flat_successors.append(state)
            except UnsupportedSyscallError:
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
                        addrs = state.se.any_n_int(target, 257)
                        if len(addrs) == 1:
                            state.add_constraints(target == addrs[0])
                        l.debug("addrs :%s", addrs)
                else:
                    addrs = state.se.any_n_int(target, 257)

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
                        self.flat_successors.append(split_state)
                    self.successors.append(state)
            except SimSolverModeError:
                self.unsat_successors.append(state)

        return state


    # misc stuff
    @staticmethod
    def _resolve_syscall(state):
        if state.os_name in SyscallCC[state.arch.name]:
            cc = SyscallCC[state.arch.name][state.os_name](state.arch)
        else:
            # Use the default syscall calling convention - it may bring problems
            cc = SyscallCC[state.arch.name]['default'](state.arch)

        syscall_num = cc.syscall_num(state)

        if syscall_num.symbolic and o.NO_SYMBOLIC_SYSCALL_RESOLUTION in state.options:
            l.debug("Not resolving symbolic syscall number")
            return syscall_num, None
        maximum = state.posix.maximum_symbolic_syscalls
        possible = state.se.any_n_int(syscall_num, maximum + 1)

        if len(possible) == 0:
            raise UnsupportedSyscallError("Unsatisfiable state attempting to do a syscall")

        if len(possible) > maximum:
            l.warning("Too many possible syscalls. Concretizing to 1.")
            possible = possible[:1]

        l.debug("Possible syscall values: %s", possible)

        return syscall_num, possible

    @contextlib.contextmanager
    def as_inline(self):
        old_bbl_addr = self.active_state.scratch.bbl_addr
        old_sim_procedure = self.active_state.scratch.sim_procedure
        old_inline = self.inline

        yield

        self.active_state.scratch.bbl_addr = old_bbl_addr
        self.active_state.scratch.sim_procedure = old_sim_procedure
        self.inline = old_inline


from simuvex.plugins.inspect import BP_BEFORE, BP_AFTER
from simuvex.s_errors import SimSolverModeError, UnsupportedSyscallError
from simuvex.s_cc import SyscallCC
from simuvex.s_action_object import _raw_ast
from .. import s_options as o
