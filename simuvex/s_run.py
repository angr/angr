#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_run")

import claripy
from claripy.ast.bv import BV

from . import s_options as o
from .plugins.inspect import BP_BEFORE, BP_AFTER
from .s_cc import SyscallCC
from .s_errors import UnsupportedSyscallError

class SimRun(object):
    def __init__(self, state, addr=None, inline=False, custom_name=None):
        # The address of this SimRun
        self.addr = addr

        # state stuff
        self.initial_state = state
        self._inline = inline
        if not self._inline and o.COW_STATES in self.initial_state.options:
            self.state = self.initial_state.copy()
        else:
            self.state = self.initial_state

        # clear the log (unless we're inlining)
        if not inline:
            self.state.log.clear()
            self.state.scratch.clear()

        # Initialize the custom_name to None
        self._custom_name = custom_name

        # The successors of this SimRun
        self.successors = [ ]
        self.all_successors = [ ]
        self.flat_successors = [ ]
        self.unsat_successors = [ ]
        self.unconstrained_successors = [ ]

        #l.debug("%s created with %d constraints.", self, len(self.initial_state.constraints()))

    def cleanup(self):
        # do some cleanup
        if o.DOWNSIZE_Z3 in self.initial_state.options:
            self.initial_state.downsize()

            for s in self.successors:
                s.downsize()

        # now delete the final state if the run was not inlined
        if not self._inline and hasattr(self, 'state'):
            delattr(self, 'state')

        if len(self.flat_successors) == 1 and len(self.unconstrained_successors) == 0:
            # the exit is unavoidable
            self.flat_successors[0].scratch.avoidable = False


    def add_successor(self, state, target, guard, jumpkind, exit_stmt_idx=None, source=None):
        """
        Add a successor state of the SimRun.
        This procedure stores method parameters into state.scratch, does some necessary cleaning, and then calls out to
        _add_successor() to properly put the state into successor lists (like flat_successors, etc.).

        :param state:         The successor state.
        :param target:        The target (of the jump/call/ret).
        :param guard:         The guard expression.
        :param jumpkind:      The jumpkind (call, ret, jump, or whatnot).
        :param exit_stmt_idx: The ID of the exit statement, an integer by default. 'default' stands for the default exit,
                              and None means it's not from a statement (for example, from a SimProcedure).
        :param source:        The source of the jump (i.e., the address of the basic block).
        """

        state._inspect('exit', BP_BEFORE, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)
        target = state._inspect_getattr("exit_target", target)
        guard = state._inspect_getattr("exit_guard", guard)
        jumpkind = state._inspect_getattr("exit_jumpkind", jumpkind)

        #
        # Simplification
        #

        if o.SIMPLIFY_EXIT_STATE in self.state.options:
            state.se.simplify()

        if o.SIMPLIFY_EXIT_GUARD in self.state.options:
            guard = state.se.simplify(guard)

        if o.SIMPLIFY_EXIT_TARGET in self.state.options:
            target = state.se.simplify(target)

        state.scratch.target = _raw_ast(target)
        state.scratch.jumpkind = jumpkind
        state.scratch.guard = _raw_ast(guard)
        state.scratch.source = source if source is not None else self.addr
        state.scratch.exit_stmt_idx = exit_stmt_idx

        state.add_constraints(guard)
        state.regs.ip = target

        # clean up the state
        state.options.discard(o.AST_DEPS)
        state.options.discard(o.AUTO_REFS)

        return_state = self._add_successor_state(state, target)
        state._inspect('exit', BP_AFTER, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)
        return return_state

    def _add_successor_state(self, state, target):
        """
        Append state into successor lists.

        :param state: a SimState instance
        :param target: The target (of the jump/call/ret)
        :return: The state
        """

        self.all_successors.append(state)

        # categorize the state
        if o.APPROXIMATE_GUARDS in state.options and state.se.is_false(state.scratch.guard, exact=False):
            if o.VALIDATE_APPROXIMATIONS in self.state.options:
                if state.satisfiable():
                    raise Exception('WTF')
            self.unsat_successors.append(state)
        elif o.APPROXIMATE_SATISFIABILITY in state.options and not state.se.satisfiable(exact=False):
            if o.VALIDATE_APPROXIMATIONS in self.state.options:
                if state.se.satisfiable():
                    raise Exception('WTF')
            self.unsat_successors.append(state)
        elif not state.scratch.guard.symbolic and state.se.is_false(state.scratch.guard):
            self.unsat_successors.append(state)
        elif o.LAZY_SOLVES not in state.options and not state.satisfiable():
            self.unsat_successors.append(state)
        elif o.NO_SYMBOLIC_JUMP_RESOLUTION in state.options and state.se.symbolic(target):
            self.unconstrained_successors.append(state.copy())
        elif not state.se.symbolic(target) and not state.scratch.jumpkind.startswith("Ijk_Sys"):
            # a successor with a concrete IP, and it's not a syscall
            self.successors.append(state)
            self.flat_successors.append(state.copy())
        elif state.scratch.jumpkind.startswith("Ijk_Sys"):
            # syscall
            self.successors.append(state)

            # Misuse the ip_at_syscall register to save the return address for this syscall
            # state.ip *might be* changed to be the real address of syscall SimProcedures by syscall handling code in
            # angr
            state.regs.ip_at_syscall = state.ip

            try:
                symbolic_syscall_num, concrete_syscall_nums = self._concrete_syscall_numbers(state)
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
                    self.unconstrained_successors.append(state.copy())
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

    @staticmethod
    def _concrete_syscall_numbers(state):

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

    @property
    def id_str(self):
        if self._custom_name is not None:
            if self.addr is not None:
                return "%s (at 0x%x)" % (self._custom_name, self.addr)
            else:
                return self._custom_name
        elif self.addr is not None:
            if isinstance(self.addr, BV):
                return str(self.addr)
            elif self.addr >= 0:
                return "0x%x" % self.addr
            elif self.addr == -1:
                # This is a syscall
                return 'Syscall'
            else:
                # Other negative numbers?
                return '-0x%x' % (-self.addr)
        else:
            return "uninitialized"

    def __repr__(self):
        return "<SimRun (%s) with addr %s and ID %s>" % (self.__class__.__name__, "0x%x" % self.addr if self.addr is not None else "None", self.id_str)

from .s_action_object import _raw_ast
from .s_errors import SimSolverModeError
