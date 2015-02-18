import logging

import claripy

from . import o

l = logging.getLogger("simuvex.s_cc")

class SimFunctionArgument(object):
    def __init__(self):
        pass

class SimRegArg(SimFunctionArgument):
    def __init__(self, reg_name):
        SimFunctionArgument.__init__(self)

        self.name = reg_name

    def __repr__(self):
        return "<%s>" % self.name

class SimStackArg(SimFunctionArgument):
    def __init__(self, stack_offset):
        SimFunctionArgument.__init__(self)

        self.offset = stack_offset

    def __repr__(self):
        return "[%xh]" % self.offset

class SimCC(object):
    '''
    This is the base class for all calling conventions. You should not directly instantiate this class.
    '''
    def __init__(self, arch):
        self.arch = arch
        # A list of argument positions
        self.args = None
        # A list of return value positions
        self.ret_vals = None

    def arg_reg_offsets(self):
        raise NotImplementedError()

    def set_args(self, state, args):
        """
        Sets the value @expr as being the @index-th argument of a function
        """
        bv_args = [ ]
        for expr in args:
            if type(expr) in (int, long):
                e = state.BVV(expr, state.arch.bits)
            elif type(expr) in (str,):
                e = state.BVV(expr)
            elif not isinstance(expr, claripy.A):
                raise SimCCError("can't set argument of type %s" % type(expr))
            else:
                e = expr

            if len(e) != state.arch.bits:
                raise SimCCError("all args must be %d bits long" % state.arch.bits)

            bv_args.append(e)

        reg_offsets = self.arg_reg_offsets()
        if len(args) > len(reg_offsets):
            stack_shift = (len(args) - len(reg_offsets)) * state.arch.stack_change
            sp_value = state.reg_expr('sp') + stack_shift
            state.store_reg('sp', sp_value)
        else:
            sp_value = state.reg_expr('sp')

        for index,e in reversed(tuple(enumerate(bv_args))):
            self.arg_setter(e, state, reg_offsets, sp_value, index)

    # Returns a bitvector expression representing the nth argument of a function
    def arg(self, index):
        raise NotImplementedError()

    # Sets an expression as the return value. Also updates state.
    def set_return_expr(self, expr):
        raise NotImplementedError()

    def _normalize_return_expr(self, state, expr):
        if type(expr) in (int, long):
            expr = state.BVV(expr, state.arch.bits)

        return expr

    #
    # Helper functions
    #

    # Helper function to get an argument, given a list of register locations it can be and stack information for overflows.
    def arg_getter(self, state, reg_offsets, args_mem_base, index):
        stack_step = state.arch.stack_change

        if index < len(reg_offsets):
            expr = state.reg_expr(reg_offsets[index], endness=state.arch.register_endness)
        else:
            index -= len(reg_offsets)
            mem_addr = args_mem_base + (index * stack_step)
            expr = state.mem_expr(mem_addr, stack_step, endness=state.arch.memory_endness)

        return expr

    def arg_setter(self, state, expr, reg_offsets, args_mem_base, index):
        stack_step = -state.arch.stack_change

        # Set register parameters
        if index < len(reg_offsets):
            offs = reg_offsets[index]
            state.store_reg(offs, expr, endness=state.arch.register_endness)

        # Set remaining parameters on the stack
        else:
            index -= len(reg_offsets)
            mem_addr = args_mem_base + (index * stack_step)
            state.store_mem(mem_addr, expr, endness=state.arch.memory_endness)

    @staticmethod
    def match(project, function_address, cfg=None):
        '''
        Try to decide the arguments to this function.
        `cfg` is not necessary, but providing a CFG makes our life easier and will give you a better analysis
        result (i.e. we have an idea how this function is called in its call-sites).
        If a CFG is not provided or we cannot find the given function address in the given CFG, we will generate
        a local CFG of the function to detect how it is using the arguments.
        '''
        arch = project.arch

        args = [ ]
        ret_vals = [ ]

        #
        # Determine how many arguments this function has.
        #
        func = cfg.function_manager.function(function_address)
        if func is not None:
            reg_args, stack_args = func.arguments

            for arg in reg_args:
                a = SimRegArg(project.arch.register_names[arg])
                args.append(a)

            for arg in stack_args:
                a = SimStackArg(arg)
                args.append(a)

            for c in CC:
                if c._match(project, args):
                    return c(project.arch, args, ret_vals)

        else:
            # TODO:
            pass

        # We cannot determine the calling convention of this function.

        return SimCCUnknown(arch, args, ret_vals)

    @property
    def arguments(self):
        return self.args

    def __repr__(self):
        return "SimCC"

class SimCCCdecl(SimCC):
    def __init__(self, arch, args, ret_vals):
        SimCC.__init__(self, arch)

        self.args = args

    @staticmethod
    def _match(p, args):
        if type(p.arch) is SimX86:
            pass

        # TODO: Finish it!

        return False

class SimCCSystemVAMD64(SimCC):
    regs = [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9' ]
    # sp + 0x8 is the return address
    beginning_stack_pos = 0x10

    def __init__(self, arch, args, ret_vals):
        SimCC.__init__(self, arch)

        self.args = args

        # Remove the ret address on stack
        self.args = [ i for i in self.args if not (isinstance(i, SimStackArg) and i.offset == 0x8) ]

    @staticmethod
    def _match(p, args):
        if type(p.arch) is SimAMD64:
            reg_args = [ i.name for i in args if isinstance(i, SimRegArg)]
            for r in SimCCSystemVAMD64.regs:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # There is still something left.
                # Bad!
                return False

            stack_args = [ i.offset for i in args if isinstance(i, SimStackArg) ]
            if 0x8 not in stack_args:
                # Where is the return address?
                # TODO: Are we too strict about this?
                return False

            # That's it!
            return True

        return False

    def __repr__(self):
        return "System V AMD64 - %s %s" % (self.arch.name, self.args)

class SimCCUnknown(SimCC):
    '''
    WOW an unknown calling convention!
    '''
    def __init__(self, arch, args, ret_vals):
        SimCC.__init__(self, arch)

        self.args = args
        self.ret_vals = ret_vals

    def arg_reg_offsets(self):
        pass

    @staticmethod
    def _match(p, args):

        # It always returns True
        return True

    def __repr__(self):
        s = "UnknownCC - %s %s" % (self.arch.name, self.args)
        return s

CC = [ SimCCCdecl, SimCCSystemVAMD64, SimCCUnknown ]

from .s_errors import SimCCError
from .s_arch import SimX86, SimAMD64
