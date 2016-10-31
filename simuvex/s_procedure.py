#!/usr/bin/env python

import types
import logging
import inspect
import itertools
import contextlib
l = logging.getLogger(name = "simuvex.s_procedure")

symbolic_count = itertools.count()

import pyvex
import claripy

from .s_cc import DefaultCC
from .plugins.inspect import BP_BEFORE, BP_AFTER

@contextlib.contextmanager
def _with_autorefs(state):
        # prepare and run!
        if o.AUTO_REFS not in state.options:
            cleanup_options = True
            state.options.add(o.AST_DEPS)
            state.options.add(o.AUTO_REFS)
        else:
            cleanup_options = False

        yield

        if cleanup_options:
            state.options.discard(o.AST_DEPS)
            state.options.discard(o.AUTO_REFS)

class SimProcedure(object):
    local_vars = ()

    NO_RET = False
    ADDS_EXITS = False
    IS_SYSCALL = False

    def __init__(
        self, arch,
        symbolic_return=None,
        returns=None, is_syscall=None,
        num_args=None, display_name=None, ret_to=None,
        stmt_from=None, convention=None, sim_kwargs=None
    ):
        self.kwargs = { } if sim_kwargs is None else sim_kwargs

        self.stmt_from = -1 if stmt_from is None else stmt_from
        self.ret_to = ret_to
        self.display_name = display_name

        # types
        self.argument_types = { } # a dictionary of index-to-type (i.e., type of arg 0: SimTypeString())
        self.return_type = None
        self.arch = arch
        self.symbolic_return = symbolic_return

        # calling convention
        self.cc = None
        self.set_convention(convention)

        # set some properties about the type of procedure this is
        self.returns = returns if returns is not None else not self.NO_RET
        self.is_syscall = is_syscall if is_syscall is not None else self.IS_SYSCALL
        self.display_name = None

        if num_args is None:
            run_spec = inspect.getargspec(self.run)
            self.num_args = len(run_spec.args) - (len(run_spec.defaults) if run_spec.defaults is not None else 0) - 1
        else:
            self.num_args = num_args

        # properties used at procedure runtime
        self.current_request = None
        self.arguments = None
        self.ret_expr = None

    def setup_and_run(self, request, run_func_name='run', *args, **kwargs):
        # check to see if this is a syscall and if we should override its return value
        override = None
        if self.is_syscall:
            request.state._inspect('syscall', BP_BEFORE, syscall_name=self.display_name)
            request.state.scratch.executed_syscall_count = 1
            if len(request.state.posix.queued_syscall_returns):
                override = request.state.posix.queued_syscall_returns.pop(0)

        if request.inline:
            old_bbl_addr = request.state.scratch.bbl_addr
            old_sim_procedure = request.state.scratch.sim_procedure

        if isinstance(override, types.FunctionType):
            try:
                override(request.state, run=self)
            except TypeError:
                override(request.state)
            r = None
            return
        elif override is not None:
            r = override
        else:
            self.current_request = request
            self.arguments = args

            # get the arguments
            sim_args = [ self.arg(_) for _ in xrange(self.num_args) ]
            sim_kwargs = dict(self.kwargs)
            sim_kwargs.update(kwargs)

            # run it
            run_func = getattr(self, run_func_name)
            r = run_func(*sim_args, **sim_kwargs)

        if self.returns:
            self.ret(r)

        if self.is_syscall:
            request.state._inspect('syscall', BP_AFTER)

        if request.inline:
            # If this is an inlined call, restore old scratch members
            request.state.scratch.bbl_addr = old_bbl_addr
            request.state.scratch.sim_procedure = old_sim_procedure

        return r

    def run(self, *args, **kwargs): #pylint:disable=unused-argument
        raise SimProcedureError("%s does not implement a run() method" % self.__class__.__name__)

    #
    # Some accessors
    #

    @property
    def state(self):
        return self.current_request.active_state

    #
    # Argument wrangling
    #

    def set_convention(self, convention=None):
        if convention is None:
            # default conventions
            if self.arch.name in DefaultCC:
                self.cc = DefaultCC[self.arch.name](self.arch)
            else:
                raise SimProcedureError('There is no default calling convention for architecture %s.' +
                                        ' You must specify a calling convention.',
                                        self.arch.name)

        else:
            self.cc = convention

    def set_args(self, args):
        arg_session = self.cc.arg_session
        for arg in args:
            if self.cc.is_fp_value(args):
                arg_session.next_arg(True).set_value(self.state, arg)
            else:
                arg_session.next_arg(False).set_value(self.state, arg)

    def arg(self, i):
        """
        Returns the ith argument. Raise a SimProcedureArgumentError if we don't have such an argument available.

        :param int i: The index of the argument to get
        :return: The argument
        :rtype: object
        """
        if self.arguments is not None:
            if i >= len(self.arguments):
                raise SimProcedureArgumentError("Argument %d does not exist." % i)
            r = self.arguments[i]
        else:
            r = self.cc.arg(self.state, i)

        l.debug("returning argument")
        return r

    #
    # Calling/exiting
    #

    def inline_call(self, procedure, *arguments, **sim_kwargs):
        e_args = [ self.state.se.BVV(a, self.state.arch.bits) if isinstance(a, (int, long)) else a for a in arguments ]
        p = procedure(self.state, inline=True, arguments=e_args, sim_kwargs=sim_kwargs)
        return p

    def call_out(self, addr, args, continue_at, cc=None):
        if cc is None:
            cc = self.cc

        call_state = self.state.copy()
        if isinstance(self.state.procedure_data.hook_addr, claripy.ast.Base):
            ret_addr = self.state.procedure_data.hook_addr
        else:
            ret_addr = self.state.se.BVV(self.state.procedure_data.hook_addr, self.state.arch.bits)
        saved_local_vars = zip(self.local_vars, map(lambda name: getattr(self, name), self.local_vars))
        simcallstack_entry = (self.__class__, continue_at, cc.stack_space(args), saved_local_vars, self.kwargs)
        cc.setup_callsite(call_state, ret_addr, args)
        call_state.procedure_data.callstack.append(simcallstack_entry)

        if call_state.libc.ppc64_abiv == 'ppc64_1':
            call_state.regs.r2 = self.state.mem[addr + 8:].long.resolved
            addr = call_state.mem[addr:].long.resolved
        elif call_state.arch.name in ('MIPS32', 'MIPS64'):
            call_state.regs.t9 = addr

        self.add_successor(call_state, addr, call_state.se.true, 'Ijk_Call')

        if o.DO_RET_EMULATION in self.state.options:
            ret_state = self.state.copy()
            cc.setup_callsite(ret_state, ret_addr, args)
            ret_state.procedure_data.callstack.append(simcallstack_entry)
            guard = ret_state.se.true if o.TRUE_RET_EMULATION_GUARD in ret_state.options else ret_state.se.false
            self.add_successor(ret_state, ret_addr, guard, 'Ijk_FakeRet')

    def jump(self, addr):
        self.add_successor(self.state, addr, self.state.se.true, 'Ijk_Boring')

    def exit(self, exit_code):
        self.state.options.discard(o.AST_DEPS)
        self.state.options.discard(o.AUTO_REFS)

        if isinstance(exit_code, (int, long)):
            exit_code = self.state.se.BVV(exit_code, self.state.arch.bits)
        self.state.log.add_event('terminate', exit_code=exit_code)
        self.add_successor(self.state, self.state.regs.ip, self.state.se.true, 'Ijk_Exit')

    #
    # Returning
    #

    def static_exits(self, blocks):  # pylint: disable=unused-argument
        """
        Get new exits by performing static analysis and heuristics. This is a fast and best-effort approach to get new
        exits for scenarios where states are not available (e.g. when building a fast CFG).

        :param list blocks: Blocks that are executed before reaching this SimProcedure.
        :return: A list of tuples. Each tuple is (address, jumpkind).
        :rtype: list
        """

        if self.ADDS_EXITS:
            raise SimProcedureError("static_exits() is not implemented for %s" % self)
        else:
            # This SimProcedure does not add any new exit
            return [ ]

    # Sets an expression as the return value. Also updates state.
    def set_return_expr(self, expr):
        if isinstance(expr, (int, long)):
            expr = self.state.se.BVV(expr, self.state.arch.bits)

        if o.SIMPLIFY_RETS in self.state.options:
            l.debug("... simplifying")
            l.debug("... before: %s", expr)
            expr = self.state.se.simplify(expr)
            l.debug("... after: %s", expr)

        if self.symbolic_return:
            size = len(expr)
            new_expr = self.state.se.Unconstrained("multiwrite_" + self.__class__.__name__, size) #pylint:disable=maybe-no-member
            self.state.add_constraints(new_expr == expr)
            expr = new_expr

        if self.arguments is not None:
            self.ret_expr = expr
            return
        else:
            self.cc.return_val.set_value(self.state, expr)

    # Adds an exit representing the function returning. Modifies the state.
    def ret(self, expr=None):
        if expr is not None: self.set_return_expr(expr)
        if self.arguments is not None:
            l.debug("Returning without setting exits due to 'internal' call.")
            return
        elif self.ret_to is not None:
            self.state.log.add_action(SimActionExit(self.state, self.ret_to))
            self.add_successor(self.state, self.ret_to, self.state.se.true, 'Ijk_Ret')
        else:
            if self.cleanup:
                self.state.options.discard(o.AST_DEPS)
                self.state.options.discard(o.AUTO_REFS)

            if o.KEEP_IP_SYMBOLIC in self.state.options and isinstance(self.addr, claripy.ast.Base):
                # TODO maybe i want to keep address symbolic
                s = claripy.Solver()
                addrs = s.eval(self.state.regs.ip, 257, extra_constraints=tuple(self.state.ip_constraints))
                if len(addrs) > 256:
                    addrs = self.state.se.any_n_int(self.state.regs.ip, 1)

                self.addr = addrs[0]

            ret_irsb = pyvex.IRSB(self.state.arch.ret_instruction, self.addr, self.state.arch)
            ret_simirsb = SimIRSB(self.state, ret_irsb, inline=True, addr=self.addr)
            if not ret_simirsb.flat_successors + ret_simirsb.unsat_successors:
                ret_state = ret_simirsb.default_exit
            else:
                ret_state = (ret_simirsb.flat_successors + ret_simirsb.unsat_successors)[0]

            if self.cleanup:
                self.state.options.add(o.AST_DEPS)
                self.state.options.add(o.AUTO_REFS)

            self._add_successor_state(ret_state, ret_state.scratch.target)

    def ty_ptr(self, ty):
        return SimTypePointer(self.arch, ty)

    def __repr__(self):
        if self.IS_SYSCALL:
            class_name = "syscall"
        else:
            class_name = "procedure"

        if self.display_name is not None:
            return "<%s %s>" % (class_name, self.display_name)
        else:
            return "<%s %s>" % (class_name, self.__class__.__name__)

class SimProcedureContinuation(SimProcedure):
    def setup_and_run(self, request):
        # pylint: disable=bad-super-call
        if len(state.procedure_data.callstack) == 0:
            raise SimProcedureError("Tried to run simproc continuation with empty stack")

        newstate = state.copy()
        cls, continue_at, stack_space, saved_local_vars, saved_kwargs = newstate.procedure_data.callstack.pop()

        newstate.regs.sp += stack_space
        self = object.__new__(cls)
        for name, val in saved_local_vars:
            setattr(self, name, val)

        kwargs['sim_kwargs'] = saved_kwargs
        self.__init__(newstate, *args, run_func_name=continue_at, **kwargs)
        self.initial_state = state
        return self

from . import s_options as o
from .s_errors import SimProcedureError, SimProcedureArgumentError
from .engines.vex.irsb import SimIRSB
from .s_type import SimTypePointer
from .s_action import SimActionExit
