#!/usr/bin/env python

from .s_run import SimRun, SimRunMeta
from .s_exception import SimProcedureError
from .s_helpers import get_and_remove, flagged
from .s_ref import SimRegRead, SimMemRead, SimRegWrite
from .s_irsb import SimIRSB
import itertools

import logging
l = logging.getLogger(name = "s_absfunc")

symbolic_count = itertools.count()

class SimRunProcedureMeta(SimRunMeta):
    def __call__(cls, *args, **kwargs):
        stmt_from = get_and_remove(kwargs, 'stmt_from')
        convention = get_and_remove(kwargs, 'convention')
        arguments = get_and_remove(kwargs, 'arguments')

        c = super(SimRunProcedureMeta, cls).make_run(args, kwargs)
        SimProcedure.__init__(c, stmt_from=stmt_from, convention=convention, arguments=arguments)
        if not hasattr(c.__init__, 'flagged'):
            c.__init__(*args[1:], **kwargs)
        return c

class SimProcedure(SimRun):
    __metaclass__ = SimRunProcedureMeta
    __slots__ = [ 'stmt_from', 'convention' ]

    # The SimProcedure constructor
    #
    #    calling convention is one of: "systemv_x64", "syscall", "microsoft_x64", "cdecl", "arm", "mips"
    @flagged
    def __init__(self, stmt_from=None, convention=None, arguments=None): # pylint: disable=W0231
        self.stmt_from = -1 if stmt_from is None else stmt_from
        self.convention = None
        self.set_convention(convention)
        self.arguments = arguments
        self.ret_expr = None

    def reanalyze(self, new_state=None, addr=None, stmt_from=None, convention=None):
        new_state = self.initial_state.copy() if new_state is None else new_state
        addr = self.addr if addr is None else addr
        stmt_from = self.stmt_from if stmt_from is None else stmt_from
        convention = self.convention if convention is None else convention

        return self.__class__(new_state, addr=addr, stmt_from=stmt_from, convention=convention)

    def initialize_run(self):
        pass

    def handle_run(self):
        self.handle_procedure()

    def handle_procedure(self):
        raise Exception("SimProcedure.handle_procedure() has been called. This should have been overwritten in class %s.", self.__class__)

    def set_convention(self, convention=None):
        if convention is None:
            if self.state.arch.name == "AMD64":
                convention = "systemv_x64"
            elif self.state.arch.name == "X86":
                convention = "cdecl"
            elif self.state.arch.name == "ARM":
                convention = "arm"
            elif self.state.arch.name == "MIPS":
                convention = "os2_mips"
            elif self.state.arch.name == "PPC32":
                convention = "ppc"
            elif self.state.arch.name == "MIPS32":
                convention = "mips"

        self.convention = convention

    # Helper function to get an argument, given a list of register locations it can be and stack information for overflows.
    def arg_getter(self, reg_offsets, args_mem_base, stack_step, index, add_refs=False):
        if index < len(reg_offsets):
            expr = self.state.reg_expr(reg_offsets[index])
            ref = SimRegRead(self.addr, self.stmt_from, reg_offsets[index], self.state.expr_value(expr), self.state.arch.bits/8)
        else:
            index -= len(reg_offsets)
            mem_addr = args_mem_base + (index * stack_step)
            expr = self.state.mem_expr(mem_addr, stack_step)

            ref = SimMemRead(self.addr, self.stmt_from, self.state.expr_value(mem_addr), self.state.expr_value(expr), self.state.arch.bits/8, addr_reg_deps=(self.state.arch.sp_offset,))

        if add_refs: self.add_refs(ref)
        return expr

    def get_arg_reg_offsets(self):
        if self.convention == "cdecl" and self.state.arch.name == "X86":
            reg_offsets = [ ] # all on stack
        elif self.convention == "systemv_x64" and self.state.arch.name == "AMD64":
            reg_offsets = [ 72, 64, 32, 24, 80, 88 ] # rdi, rsi, rdx, rcx, r8, r9
        elif self.convention == "syscall" and self.state.arch.name == "AMD64":
            reg_offsets = [ 72, 64, 32, 24, 80, 88 ] # rdi, rsi, rdx, rcx, r8, r9
        elif self.convention == "arm" and self.state.arch.name == "ARM":
            reg_offsets = [ 8, 12, 16, 20 ] # r0, r1, r2, r3
        elif self.convention == "ppc" and self.state.arch.name == "PPC32":
            reg_offsets = [ 28, 32, 36, 40, 44, 48, 52, 56 ] # r3 through r10
        elif self.convention == "mips" and self.state.arch.name == "MIPS32":
            reg_offsets = [ 16, 20, 24, 28 ] # r4 through r7
        else:
            raise SimProcedureError("Unsupported arch %s and calling convention %s for getting register offsets", self.state.arch.name, self.convention)
        return reg_offsets

    # Returns a bitvector expression representing the nth argument of a function
    def peek_arg_expr(self, index, add_refs=False):
        if self.arguments is not None:
            return self.arguments[index]

        if self.convention in ("systemv_x64", "syscall") and self.state.arch.name == "AMD64":
            reg_offsets = self.get_arg_reg_offsets()
            return self.arg_getter(reg_offsets, self.state.reg_expr(self.state.arch.sp_offset) + 8, 8, index, add_refs=add_refs)
        elif self.convention == "cdecl" and self.state.arch.name == "X86":
            reg_offsets = self.get_arg_reg_offsets()
            return self.arg_getter(reg_offsets, self.state.reg_expr(self.state.arch.sp_offset) + 4, 4, index, add_refs=add_refs)
        elif self.convention == "arm" and self.state.arch.name == "ARM":
            reg_offsets = self.get_arg_reg_offsets()
            return self.arg_getter(reg_offsets, self.state.reg_expr(36), 4, index, add_refs=add_refs)
        elif self.convention == "ppc" and self.state.arch.name == "PPC32":
            reg_offsets = self.get_arg_reg_offsets()
            # TODO: figure out how to get at the other arguments (I think they're just passed on the stack)
            return self.arg_getter(reg_offsets, None, 4, index, add_refs=add_refs)
        elif self.convention == "mips" and self.state.arch.name == "MIPS32":
            reg_offsets = self.get_arg_reg_offsets()
            return self.arg_getter(reg_offsets, self.state.reg_expr(116), 4, index, add_refs=add_refs)

        raise SimProcedureError("Unsupported calling convention %s for arguments" % self.convention)

    def peek_arg_value(self, index):
        return self.state.expr_value(self.peek_arg_expr(index))

    # Returns a bitvector expression representing the nth argument of a function, and add refs
    def get_arg_expr(self, index):
        return self.peek_arg_expr(index, add_refs=True)

    def get_arg_value(self, index):
        return self.state.expr_value(self.get_arg_expr(index))

    def inline_call(self, procedure, *arguments, **sim_args):
        p = procedure(self.state, inline=True, arguments=arguments, **sim_args)
        self.copy_refs(p)
        return p

    # Sets an expression as the return value. Also updates state.
    def set_return_expr(self, expr):
        if self.arguments is not None:
            self.ret_expr = expr
            return

        if self.state.arch.name == "AMD64":
            self.state.store_reg(16, expr)
            self.add_refs(SimRegWrite(self.addr, self.stmt_from, 16, self.state.expr_value(expr), 8))
        elif self.state.arch.name == "X86":
            self.state.store_reg(8, expr)
            self.add_refs(SimRegWrite(self.addr, self.stmt_from, 8, self.state.expr_value(expr), 4))
        elif self.state.arch.name == "ARM":
            self.state.store_reg(8, expr)
            self.add_refs(SimRegWrite(self.addr, self.stmt_from, 8, self.state.expr_value(expr), 4))
        elif self.state.arch.name == "PPC32":
            self.state.store_reg(28, expr)
            self.add_refs(SimRegWrite(self.addr, self.stmt_from, 28, self.state.expr_value(expr), 4))
        elif self.state.arch.name == "MIPS32":
            self.state.store_reg(8, expr)
            self.add_refs(SimRegWrite(self.addr, self.stmt_from, 8, self.state.expr_value(expr), 4))
        else:
            raise SimProcedureError("Unsupported architecture %s for returns" % self.state.arch)

    # Adds an exit representing the function returning. Modifies the state.
    def exit_return(self, expr=None):
        if expr is not None: self.set_return_expr(expr)
        if self.arguments is not None:
            l.debug("Returning without setting exits due to 'internal' call.")
            return

        ret_irsb = self.state.arch.get_ret_irsb(self.addr)
        ret_sirsb = SimIRSB(self.state, ret_irsb, addr=self.addr)
        self.copy_exits(ret_sirsb)
        self.copy_refs(ret_sirsb)

    def __repr__(self):
        return "<SimProcedure %s>" % self.__class__.__name__
