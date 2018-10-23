import inspect
import copy
import itertools
from cle import Symbol

import logging
l = logging.getLogger("angr.sim_procedure")

symbolic_count = itertools.count()


class SimProcedure:
    """
    A SimProcedure is a wonderful object which describes a procedure to run on a state.

    You may subclass SimProcedure and override ``run()``, replacing it with mutating ``self.state`` however you like,
    and then either returning a value or jumping away somehow.

    A detailed discussion of programming SimProcedures may be found at https://docs.angr.io/docs/simprocedures.md

    :param arch:            The architecture to use for this procedure

    The following parameters are optional:

    :param symbolic_return: Whether the procedure's return value should be stubbed into a
                            single symbolic variable constratined to the real return value
    :param returns:         Whether the procedure should return to its caller afterwards
    :param is_syscall:      Whether this procedure is a syscall
    :param num_args:        The number of arguments this procedure should extract
    :param display_name:    The name to use when displaying this procedure
    :param cc:              The SimCC to use for this procedure
    :param sim_kwargs:      Additional keyword arguments to be passed to run()
    :param is_function:     Whether this procedure emulates a function
    """
    def __init__(
        self, project=None, cc=None, symbolic_return=None,
        returns=None, is_syscall=False, is_stub=False,
        num_args=None, display_name=None, library_name=None,
        is_function=None, **kwargs
    ):
        # WE'LL FIGURE IT OUT
        self.project = project
        self.arch = project.arch if project is not None else None
        self.addr = None
        self.cc = cc
        self.canonical = self

        self.kwargs = kwargs
        self.display_name = type(self).__name__ if display_name is None else display_name
        self.library_name = library_name
        self.syscall_number = None
        self.abi = None
        self.symbolic_return = symbolic_return

        # types
        self.argument_types = { } # a dictionary of index-to-type (i.e., type of arg 0: SimTypeString())
        self.return_type = None

        # set some properties about the type of procedure this is
        self.returns = returns if returns is not None else not self.NO_RET
        self.is_syscall = is_syscall
        self.is_function = is_function if is_function is not None else self.IS_FUNCTION
        self.is_stub = is_stub
        self.is_continuation = False
        self.continuations = {}
        self.run_func = 'run'

        # Get the concrete number of arguments that should be passed to this procedure
        if num_args is None:
            run_spec = inspect.getargspec(self.run)
            self.num_args = len(run_spec.args) - (len(run_spec.defaults) if run_spec.defaults is not None else 0) - 1
        else:
            self.num_args = num_args

        # runtime values
        self.state = None
        self.successors = None
        self.arguments = None
        self.use_state_arguments = True
        self.ret_to = None
        self.ret_expr = None
        self.call_ret_expr = None
        self.inhibit_autoret = None

    def __repr__(self):
        return "<SimProcedure %s%s%s%s%s>" % self._describe_me()

    def _describe_me(self):
        """
        return a 5-tuple of strings sufficient for formatting with ``%s%s%s%s%s`` to verbosely describe the procedure
        """
        return (
            self.display_name,
            ' (cont: %s)' % self.run_func if self.is_continuation else '',
            ' (syscall)' if self.is_syscall else '',
            ' (inline)' if not self.use_state_arguments else '',
            ' (stub)' if self.is_stub else '',
        )

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        """
        Call this method with a SimState and a SimSuccessors to execute the procedure.

        Alternately, successors may be none if this is an inline call. In that case, you should
        provide arguments to the function.
        """
        # fill out all the fun stuff we don't want to frontload
        if self.addr is None and not state.regs.ip.symbolic:
            self.addr = state.addr
        if self.arch is None:
            self.arch = state.arch
        if self.project is None:
            self.project = state.project
        if self.cc is None:
            if self.arch.name in DEFAULT_CC:
                self.cc = DEFAULT_CC[self.arch.name](self.arch)
            else:
                raise SimProcedureError('There is no default calling convention for architecture %s.'
                                        ' You must specify a calling convention.' % self.arch.name)

        inst = copy.copy(self)
        inst.state = state
        inst.successors = successors
        inst.ret_to = ret_to
        inst.inhibit_autoret = False

        # check to see if this is a syscall and if we should override its return value
        override = None
        if inst.is_syscall:
            state.history.recent_syscall_count = 1
            if len(state.posix.queued_syscall_returns):
                override = state.posix.queued_syscall_returns.pop(0)

        if callable(override):
            try:
                r = override(state, run=inst)
            except TypeError:
                r = override(state)
            inst.use_state_arguments = True

        elif override is not None:
            r = override
            inst.use_state_arguments = True

        else:
            # get the arguments

            # handle if this is a continuation from a return
            if inst.is_continuation:
                if state.callstack.top.procedure_data is None:
                    raise SimProcedureError("Tried to return to a SimProcedure in an inapplicable stack frame!")

                saved_sp, sim_args, saved_local_vars, saved_lr = state.callstack.top.procedure_data
                state.regs.sp = saved_sp
                if saved_lr is not None:
                    state.regs.lr = saved_lr
                inst.arguments = sim_args
                inst.use_state_arguments = True
                inst.call_ret_expr = state.registers.load(state.arch.ret_offset, state.arch.bytes, endness=state.arch.register_endness)
                for name, val in saved_local_vars:
                    setattr(inst, name, val)
            else:
                if arguments is None:
                    inst.use_state_arguments = True
                    sim_args = [ inst.arg(_) for _ in range(inst.num_args) ]
                    inst.arguments = sim_args
                else:
                    inst.use_state_arguments = False
                    sim_args = arguments[:inst.num_args]
                    inst.arguments = arguments

            # run it
            l.debug("Executing %s%s%s%s%s with %s, %s", *(inst._describe_me() + (sim_args, inst.kwargs)))
            r = getattr(inst, inst.run_func)(*sim_args, **inst.kwargs)

        if inst.returns and inst.is_function and not inst.inhibit_autoret:
            inst.ret(r)

        return inst

    def make_continuation(self, name):
        # make a copy of the canon copy, customize it for the specific continuation, then hook it
        if name not in self.canonical.continuations:
            cont = copy.copy(self.canonical)
            target_name = '%s.%s' % (self.display_name, name)
            should_be_none = self.project.loader.extern_object.get_symbol(target_name)
            if should_be_none is None:
                cont.addr = self.project.loader.extern_object.make_extern(target_name, sym_type=Symbol.TYPE_OTHER).rebased_addr
            else:
                l.error("Trying to make continuation %s but it already exists. This is bad.", target_name)
                cont.addr = self.project.loader.extern_object.allocate()
            cont.is_continuation = True
            cont.run_func = name
            self.canonical.continuations[name] = cont
            self.project.hook(cont.addr, cont)
        return self.canonical.continuations[name].addr

    #
    # Implement these in a subclass of SimProcedure!
    #

    NO_RET = False          # set this to true if control flow will never return from this function
    ADDS_EXITS = False      # set this to true if you do any control flow other than returning
    IS_FUNCTION = True      # does this procedure simulate a function?
    ARGS_MISMATCH = False   # does this procedure have a different list of arguments than what is provided in the
                            # function specification? This may happen when we manually extract arguments in the run()
                            # method of a SimProcedure.

    local_vars = ()         # if you use self.call(), set this to a list of all the local variable
                            # names in your class. They will be restored on return.

    def run(self, *args, **kwargs): # pylint: disable=unused-argument
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
    # misc properties
    #

    @property
    def should_add_successors(self):
        return self.successors is not None

    #
    # Working with calling conventions
    #

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
        if self.use_state_arguments:
            r = self.cc.arg(self.state, i)
        else:
            if i >= len(self.arguments):
                raise SimProcedureArgumentError("Argument %d does not exist." % i)
            r = self.arguments[i]           # pylint: disable=unsubscriptable-object

        l.debug("returning argument")
        return r

    #
    # Control Flow
    #

    def inline_call(self, procedure, *arguments, **kwargs):
        """
        Call another SimProcedure in-line to retrieve its return value.
        Returns an instance of the procedure with the ret_expr property set.

        :param procedure:       The class of the procedure to execute
        :param arguments:       Any additional positional args will be used as arguments to the
                                procedure call
        :param sim_kwargs:      Any additional keyword args will be passed as sim_kwargs to the
                                procedure construtor
        """
        e_args = [ self.state.solver.BVV(a, self.state.arch.bits) if isinstance(a, int) else a for a in arguments ]
        p = procedure(project=self.project, **kwargs)
        return p.execute(self.state, None, arguments=e_args)

    def ret(self, expr=None):
        """
        Add an exit representing a return from this function.
        If this is not an inline call, grab a return address from the state and jump to it.
        If this is not an inline call, set a return expression with the calling convention.
        """
        self.inhibit_autoret = True

        if expr is not None:
            if o.SIMPLIFY_RETS in self.state.options:
                l.debug("... simplifying")
                l.debug("... before: %s", expr)
                expr = self.state.solver.simplify(expr)
                l.debug("... after: %s", expr)

            if self.symbolic_return:
                size = len(expr)
                new_expr = self.state.solver.Unconstrained(
                        "symbolic_return_" + self.display_name,
                        size,
                        key=('symbolic_return', self.display_name)) #pylint:disable=maybe-no-member
                self.state.add_constraints(new_expr == expr)
                expr = new_expr

            self.ret_expr = expr

        ret_addr = None
        if self.use_state_arguments:
            ret_addr = self.cc.teardown_callsite(
                    self.state,
                    expr,
                    arg_types=[False]*self.num_args if self.cc.args is None else None)

        if not self.should_add_successors:
            l.debug("Returning without setting exits due to 'internal' call.")
            return

        if self.ret_to is not None:
            ret_addr = self.ret_to

        if ret_addr is None:
            raise SimProcedureError("No source for return address in ret() call!")

        self._exit_action(self.state, ret_addr)
        self.successors.add_successor(self.state, ret_addr, self.state.solver.true, 'Ijk_Ret')

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
        self.inhibit_autoret = True

        if cc is None:
            cc = self.cc

        call_state = self.state.copy()
        ret_addr = self.make_continuation(continue_at)
        saved_local_vars = list(zip(self.local_vars, map(lambda name: getattr(self, name), self.local_vars)))
        simcallstack_entry = (self.state.regs.sp, self.arguments, saved_local_vars, self.state.regs.lr if self.state.arch.lr_offset is not None else None)
        cc.setup_callsite(call_state, ret_addr, args)
        call_state.callstack.top.procedure_data = simcallstack_entry

        # TODO: Move this to setup_callsite?
        if call_state.libc.ppc64_abiv == 'ppc64_1':
            call_state.regs.r2 = self.state.mem[addr + 8:].long.resolved
            addr = call_state.mem[addr:].long.resolved
        elif call_state.arch.name in ('MIPS32', 'MIPS64'):
            call_state.regs.t9 = addr

        self._exit_action(call_state, addr)
        self.successors.add_successor(call_state, addr, call_state.solver.true, 'Ijk_Call')

        if o.DO_RET_EMULATION in self.state.options:
            # we need to set up the call because the continuation will try to tear it down
            ret_state = self.state.copy()
            cc.setup_callsite(ret_state, ret_addr, args)
            ret_state.callstack.top.procedure_data = simcallstack_entry
            guard = ret_state.solver.true if o.TRUE_RET_EMULATION_GUARD in ret_state.options else ret_state.solver.false
            self.successors.add_successor(ret_state, ret_addr, guard, 'Ijk_FakeRet')

    def jump(self, addr):
        """
        Add an exit representing jumping to an address.
        """
        self.inhibit_autoret = True
        self._exit_action(self.state, addr)
        self.successors.add_successor(self.state, addr, self.state.solver.true, 'Ijk_Boring')

    def exit(self, exit_code):
        """
        Add an exit representing terminating the program.
        """
        self.inhibit_autoret = True
        self.state.options.discard(o.AST_DEPS)
        self.state.options.discard(o.AUTO_REFS)

        if isinstance(exit_code, int):
            exit_code = self.state.solver.BVV(exit_code, self.state.arch.bits)
        self.state.history.add_event('terminate', exit_code=exit_code)
        self.successors.add_successor(self.state, self.state.regs.ip, self.state.solver.true, 'Ijk_Exit')

    @staticmethod
    def _exit_action(state, addr):
        if o.TRACK_JMP_ACTIONS in state.options:
            state.history.add_action(SimActionExit(state, addr))

    #
    # misc
    #

    def ty_ptr(self, ty):
        return SimTypePointer(self.arch, ty)

from . import sim_options as o
from angr.errors import SimProcedureError, SimProcedureArgumentError
from angr.sim_type import SimTypePointer
from angr.state_plugins.sim_action import SimActionExit
from angr.calling_conventions import DEFAULT_CC
