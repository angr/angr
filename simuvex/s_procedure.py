#!/usr/bin/env python

import inspect
import itertools

import logging
l = logging.getLogger(name = "simuvex.s_procedure")

symbolic_count = itertools.count()

from .s_run import SimRun
from .s_cc import DefaultCC

class SimProcedure(SimRun):
    ADDS_EXITS = False
    NO_RET = False

    def __init__(self, state, ret_to=None, stmt_from=None, convention=None, arguments=None, sim_kwargs=None, **kwargs):
        self.kwargs = { } if sim_kwargs is None else sim_kwargs
        SimRun.__init__(self, state, **kwargs)

        self.state.scratch.bbl_addr = self.addr

        self.stmt_from = -1 if stmt_from is None else stmt_from
        self.arguments = arguments
        self.ret_to = ret_to
        self.ret_expr = None
        self.symbolic_return = False
        self.state.scratch.sim_procedure = self.__class__.__name__

        # types
        self.argument_types = { } # a dictionary of index-to-type (i.e., type of arg 0: SimTypeString())
        self.return_type = None

        # calling convention
        self.cc = None
        self.set_convention(convention)

        # prepare and run!
        if o.AUTO_REFS not in self.state.options:
            cleanup_options = True
            self.state.options.add(o.AST_DEPS)
            self.state.options.add(o.AUTO_REFS)
        else:
            cleanup_options = False

        run_spec = inspect.getargspec(self.run)
        num_args = len(run_spec.args) - (len(run_spec.defaults) if run_spec.defaults is not None else 0) - 1
        args = [ self.arg(_) for _ in xrange(num_args) ]

        r = self.run(*args, **self.kwargs)

        if r is not None:
            self.ret(r)

        if o.FRESHNESS_ANALYSIS in self.state.options:
            self.state.scratch.update_ignored_variables()

        if cleanup_options:
            self.state.options.discard(o.AST_DEPS)
            self.state.options.discard(o.AUTO_REFS)

    def run(self, *args, **kwargs): #pylint:disable=unused-argument
        raise SimProcedureError("%s does not implement a run() method" % self.__class__.__name__)

    def reanalyze(self, new_state=None, addr=None, stmt_from=None, convention=None):
        new_state = self.initial_state.copy() if new_state is None else new_state
        addr = self.addr if addr is None else addr
        stmt_from = self.stmt_from if stmt_from is None else stmt_from
        cc = self.cc if convention is None else convention

        return self.__class__(new_state, addr=addr, stmt_from=stmt_from, convention=cc, sim_kwargs=self.kwargs) #pylint:disable=E1124,E1123

    def initialize_run(self):
        pass

    def handle_run(self):
        self.handle_procedure()

    def handle_procedure(self):
        raise Exception("SimProcedure.handle_procedure() has been called. This should have been overwritten in class %s.", self.__class__)

    def set_convention(self, convention=None):
        if convention is None:
            # default conventions
            if self.state.arch.name in DefaultCC:
                self.cc = DefaultCC[self.state.arch.name](self.state.arch)
            else:
                raise SimProcedureError('There is no default calling convention for architecture %s.' +
                                        ' You must specify a calling convention.',
                                        self.state.arch.name)

        else:
            self.cc = convention

    def set_args(self, args):
        """
        Sets the value @expr as being the @index-th argument of a function
        """

        self.cc.set_args(self.state, args)

    # Returns a bitvector expression representing the nth argument of a function
    def arg(self, index):
        if self.arguments is not None:
            r = self.arguments[index]
        else:
            r = self.cc.arg(self.state, index)

        l.debug("returning argument")
        return r

    def inline_call(self, procedure, *arguments, **sim_kwargs):
        e_args = [ self.state.BVV(a, self.state.arch.bits) if isinstance(a, (int, long)) else a for a in arguments ]
        p = procedure(self.state, inline=True, arguments=e_args, sim_kwargs=sim_kwargs)
        return p

    # Sets an expression as the return value. Also updates state.
    def set_return_expr(self, expr):
        if isinstance(expr, (int, long)):
            expr = self.state.BVV(expr, self.state.arch.bits)

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
            self.cc.set_return_expr(self.state, expr)

    # Adds an exit representing the function returning. Modifies the state.
    def ret(self, expr=None):
        if expr is not None: self.set_return_expr(expr)
        if self.arguments is not None:
            l.debug("Returning without setting exits due to 'internal' call.")
            return
        elif self.ret_to is not None:
            self.add_successor(self.state, self.ret_to, self.state.se.true, 'Ijk_Ret')
        else:
            if self.cleanup:
                self.state.options.discard(o.AST_DEPS)
                self.state.options.discard(o.AUTO_REFS)

            ret_irsb = self.state.arch.disassemble_vex(self.state.arch.ret_instruction, mem_addr=self.addr)
            ret_simirsb = SimIRSB(self.state, ret_irsb, inline=True, addr=self.addr)
            if not ret_simirsb.flat_successors + ret_simirsb.unsat_successors:
                ret_state = ret_simirsb.default_exit
            else:
                ret_state = (ret_simirsb.flat_successors + ret_simirsb.unsat_successors)[0]

            if self.cleanup:
                self.state.options.add(o.AST_DEPS)
                self.state.options.add(o.AUTO_REFS)

            self.add_successor(ret_state, ret_state.scratch.target, ret_state.scratch.guard, ret_state.scratch.jumpkind)

    def ty_ptr(self, ty):
        return SimTypePointer(self.state.arch, ty)

    def __repr__(self):
        if self._custom_name is not None:
            return "<SimProcedure %s>" % self._custom_name
        else:
            return "<SimProcedure %s>" % self.__class__.__name__

from . import s_options as o
from .s_errors import SimProcedureError
from .vex.irsb import SimIRSB
from .s_type import SimTypePointer
