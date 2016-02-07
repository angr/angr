#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_run")
import claripy
import simuvex.s_options as o
from claripy.ast.bv import BV

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

        # now delete the final state; it should be exported in exits
        if hasattr(self, 'state'):
            delattr(self, 'state')

    def add_successor(self, state, target, guard, jumpkind, exit_stmt_idx=None, source=None):
        '''
        Add a successor state of the SimRun.
        This procedure stores method parameters into state.scratch, does some necessary cleaning, and then calls out to
        _add_successor() to properly put the state into successor lists (like flat_successors, etc.).

        @param state: the successor state
        @param target: the target (of the jump/call/ret)
        @param guard: the guard expression
        @param jumpkind: the jumpkind (call, ret, jump, or whatnot)
        @param exit_stmt_idx: ID of the exit statement, an integer by default. 'default' stands for the default exit,
                              and None means it's not from a statement (for example, from a SimProcedure).
        @param source: the source of the jump (i.e., the address of
                       the basic block).
        '''
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

        return self._add_successor(state, target)

    def _add_successor(self, state, target):
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
        elif not state.se.symbolic(target):
            self.successors.append(state)
            self.flat_successors.append(state.copy())
        else:
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
                    l.warning("Exit state has over 257 possible solutions. Likely unconstrained; skipping. %s", target)
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
