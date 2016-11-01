#!/usr/bin/env python

import types
import logging
import inspect
import itertools
l = logging.getLogger(name = "simuvex.s_procedure")

symbolic_count = itertools.count()

from .s_cc import DefaultCC
from .plugins.inspect import BP_BEFORE, BP_AFTER


class SimProcedure(object):
    #
    # Implement these in a subclass!
    #

    local_vars = ()

    NO_RET = False
    ADDS_EXITS = False
    IS_SYSCALL = False

    def run(self, *args, **kwargs): #pylint:disable=unused-argument
        """
        Implement the actual procedure here!
        """
        raise SimProcedureError("%s does not implement a run() method" % self.__class__.__name__)

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

    #
    # Initialization and clerical work
    #

    def __init__(
        self, arch,
        symbolic_return=None,
        returns=None, is_syscall=None,
        num_args=None, display_name=None,
        stmt_from=None, convention=None, sim_kwargs=None,
        is_function=False
    ):
        self.kwargs = { } if sim_kwargs is None else sim_kwargs

        self.stmt_from = -1 if stmt_from is None else stmt_from
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
        self.is_function = is_function

        # Get the concrete number of arguments that should be passed to this procedure
        if num_args is None:
            run_spec = inspect.getargspec(self.run)
            self.num_args = len(run_spec.args) - (len(run_spec.defaults) if run_spec.defaults is not None else 0) - 1
        else:
            self.num_args = num_args

        # properties used at procedure runtime
        self.current_request = None
        self.arguments = None
        self.ret_expr = None

    def setup_and_run(self, request, arguments=None):
        """
        Call this method with a SimEngineRequest to execute the procedure
        """
        # check to see if this is a syscall and if we should override its return value
        override = None
        if self.is_syscall:
            request.state._inspect('syscall', BP_BEFORE, syscall_name=self.display_name)
            request.state.scratch.executed_syscall_count = 1
            if len(request.state.posix.queued_syscall_returns):
                override = request.state.posix.queued_syscall_returns.pop(0)

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
            self.arguments = arguments

            # get the arguments
            if arguments is None:
                sim_args = [ self.arg(_) for _ in xrange(self.num_args) ]
            else:
                sim_args = self.arguments

            # handle if this is a continuation from a return
            if self.is_function and self.state.scratch.jumpkind == 'Ijk_Ret':
                if len(self.state.procedure_data.callstack) == 0:
                    raise SimProcedureError("Tried to run simproc continuation with empty stack")

                continue_at, stack_space, saved_local_vars = self.state.procedure_data.callstack.pop()
                run_func = getattr(self, continue_at)
                self.state.regs.sp += stack_space
                for name, val in saved_local_vars:
                    setattr(self, name, val)
            else:
                run_func = self.run

            # run it
            r = run_func(*sim_args, **self.kwargs)

        if self.returns:
            self.ret(r)

        if self.is_syscall:
            request.state._inspect('syscall', BP_AFTER)

    #
    # Some accessors
    #

    @property
    def state(self):
        return self.current_request.active_state

    @property
    def addr(self):
        return self.state.addr

    # There are two separate metrics for inline-ness that we might want to keep separate
    # there's whether the request is inline, which means that we don't add exits
    # but there's also whether the call is inline, which means that the arguments and the
    # return values should be passed around through different means.

    @property
    def is_inline_request(self):
        return self.current_request.inline

    @property
    def is_inline_call(self):
        return self.arguments is not None

    #
    # Working with calling conventions
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
        if self.is_inline_call:
            if i >= len(self.arguments):
                raise SimProcedureArgumentError("Argument %d does not exist." % i)
            r = self.arguments[i]
        else:
            r = self.cc.arg(self.state, i)

        l.debug("returning argument")
        return r

    def set_return_expr(self, expr):
        """
        Set this expression as the return value for the function.
        If this is not an inline call, this will write the expression to the state via the
        calling convention.
        """
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

        if self.is_inline_call:
            self.ret_expr = expr
        else:
            self.cc.return_val.set_value(self.state, expr)

    #
    # Calling/exiting
    #

    def inline_call(self, procedure, *arguments, **sim_kwargs):
        """
        Call another SimProcedure in-line to retrieve its return value.
        Returns an instance of the procedure with the ret_expr property set.

        :param procedure:       The class of the procedure to execute
        :param arguments:       Any additional positional args will be used as arguments to the
                                procedure call
        :param sim_kwargs:      Any additional keyword args will be passed as sim_kwargs to the
                                procedure construtor
        """
        with self.current_request.as_inline():
            e_args = [ self.state.se.BVV(a, self.state.arch.bits) if isinstance(a, (int, long)) else a for a in arguments ]
            p = procedure(self.arch, sim_kwargs=sim_kwargs)
            p.setup_and_run(self.current_request, e_args)
            return p

    def ret(self, expr=None):
        """
        Add an exit representing a return from this function.
        If this is not an inline call, grab a return address from the state and jump to it.
        If this is not an inline call, set a return expression with the calling convention.
        """
        if expr is not None:
            self.set_return_expr(expr)

        if self.is_inline_request:
            l.debug("Returning without setting exits due to 'internal' call.")
            return

        if self.current_request.ret_to is not None:
            # TODO: If set ret_to, do we also want to pop an unused ret addr from the stack?
            ret_addr = self.current_request.ret_to
        else:
            if self.state.arch.call_pushes_ret:
                ret_addr = self.state.stack_pop()
            else:
                ret_addr = self.state.registers.load(self.state.arch.lr_offset, self.state.arch.bytes)

        self._exit_action(self.state, ret_addr)
        self.current_request.add_successor(self.state, ret_addr, self.state.se.true, 'Ijk_Ret')

    def call(self, addr, args, continue_at, cc=None):
        """
        Add an exit representing calling another function via pointer.

        :param addr:        The address of the function to call
        :param args:        The list of arguments to call the function with
        :param continue_at: Later, when the called function returns, execution of the current
                            procedure will continue in the named method.
        :param cc:          Optional: use this calling convention for calling the new function.
                            Default is to use the current convention.
        """
        if cc is None:
            cc = self.cc

        call_state = self.state.copy()
        ret_addr = self.addr
        saved_local_vars = zip(self.local_vars, map(lambda name: getattr(self, name), self.local_vars))
        simcallstack_entry = (continue_at, cc.stack_space(args), saved_local_vars)
        cc.setup_callsite(call_state, ret_addr, args)
        call_state.procedure_data.callstack.append(simcallstack_entry)

        if call_state.libc.ppc64_abiv == 'ppc64_1':
            call_state.regs.r2 = self.state.mem[addr + 8:].long.resolved
            addr = call_state.mem[addr:].long.resolved
        elif call_state.arch.name in ('MIPS32', 'MIPS64'):
            call_state.regs.t9 = addr

        self._exit_action(call_state, addr)
        self.current_request.add_successor(call_state, addr, call_state.se.true, 'Ijk_Call')

        if o.DO_RET_EMULATION in self.state.options:
            ret_state = self.state.copy()
            cc.setup_callsite(ret_state, ret_addr, args)
            ret_state.procedure_data.callstack.append(simcallstack_entry)
            guard = ret_state.se.true if o.TRUE_RET_EMULATION_GUARD in ret_state.options else ret_state.se.false
            self.current_request.add_successor(ret_state, ret_addr, guard, 'Ijk_FakeRet')

    def jump(self, addr):
        """
        Add an exit representing jumping to an address.
        """
        self._exit_action(self.state, addr)
        self.current_request.add_successor(self.state, addr, self.state.se.true, 'Ijk_Boring')

    def exit(self, exit_code):
        """
        Add an exit representing terminating the program.
        """
        self.state.options.discard(o.AST_DEPS)
        self.state.options.discard(o.AUTO_REFS)

        if isinstance(exit_code, (int, long)):
            exit_code = self.state.se.BVV(exit_code, self.state.arch.bits)
        self.state.log.add_event('terminate', exit_code=exit_code)
        self.current_request.add_successor(self.state, self.state.regs.ip, self.state.se.true, 'Ijk_Exit')

    def _exit_action(self, state, addr):
        if o.TRACK_JMP_ACTIONS in state.options:
            state.log.add_action(SimActionExit(state, addr))

    #
    # misc
    #

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

from . import s_options as o
from .s_errors import SimProcedureError, SimProcedureArgumentError
from .s_type import SimTypePointer
from .s_action import SimActionExit
