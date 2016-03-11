import logging

import claripy
from archinfo import ArchX86, ArchAMD64, ArchARM, ArchAArch64, ArchMIPS32, ArchMIPS64, ArchPPC32, ArchPPC64

from .s_action_object import SimActionObject

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
    RET_VAL_REG = None
    ARG_REGS = None
    STACKARG_SP_DIFF = None
    STACKARG_SP_BUFF = 0

    def __init__(self, arch, args=None, ret_vals=None, sp_delta=None):
        self.arch = arch
        self.sp_delta = sp_delta

        # A list of argument positions
        self.args = args
        # A list of return value positions
        self.ret_vals = ret_vals

    def setup_callsite(self, state, ret_addr, args):
        self.set_args(state, args)
        self.set_return_addr(state, ret_addr)

    def set_return_addr(self, state, addr):
        raise NotImplementedError()

    def set_args(self, state, args):
        """
        Sets the value @expr as being the @index-th argument of a function
        """

        # Normalize types of all arguments
        bv_args = [ ]
        for expr in args:
            if isinstance(expr, (int, long)):
                e = state.se.BVV(expr, state.arch.bits)
            elif isinstance(expr, (str,)):
                e = state.se.BVV(expr)
            elif not isinstance(expr, (claripy.ast.Base, SimActionObject)):
                raise SimCCError("can't set argument of type %s" % type(expr))
            else:
                e = expr

            if len(e) != state.arch.bits:
                raise SimCCError("all args must be %d bits long" % state.arch.bits)

            bv_args.append(e)

        reg_offsets = self.ARG_REGS
        if reg_offsets is None:
            raise NotImplementedError('ARG_REGS is not specified for calling convention %s' % type(self))

        state.regs.sp = state.regs.sp - self.stack_space(state, args)

        for index, arg in enumerate(bv_args):
            self.arg_setter(state, arg, reg_offsets, state.regs.sp, index)

    def stack_space(self, state, args):
        '''
         returns the number of bytes needed on the stack for the arguments passed,
         i.e. the number of bytes set_args allocates.
        '''
        stack_shift = 0
        if len(args) > len(self.ARG_REGS):
            stack_shift = (len(args) - len(self.ARG_REGS)) * state.arch.stack_change

        return self.STACKARG_SP_BUFF - stack_shift


    # Returns a bitvector expression representing the nth argument of a function
    def arg(self, state, index, stackarg_mem_base=None):
        reg_offsets = self.ARG_REGS
        if reg_offsets is None:
            raise NotImplementedError('ARG_REGS is not specified for calling convention %s' % type(self))

        if self.STACKARG_SP_DIFF is None:
            raise NotImplementedError('STACKARG_SP_DIFF is not specified for calling convention %s' % type(self))

        if stackarg_mem_base is None:
            # This is the default case, which is used inside SimProcedures.
            stackarg_mem_base = state.regs.sp + self.STACKARG_SP_DIFF

        return self.arg_getter(state, reg_offsets, stackarg_mem_base, index)

    # Sets an expression as the return value. Also updates state.
    def set_return_expr(self, state, expr):
        expr = self._normalize_return_expr(state, expr)

        if self.RET_VAL_REG is None:
            raise NotImplementedError('RET_VAL_REG is not specified for calling convention %s' % type(self))

        state.registers.store(self.RET_VAL_REG, expr)

    def get_return_expr(self, state):
        if self.RET_VAL_REG is None:
            raise NotImplementedError('RET_VAL_REG is not specified for calling convention %s' % type(self))

        return state.registers.load(self.RET_VAL_REG)

    @staticmethod
    def _normalize_return_expr(state, expr):
        if isinstance(expr, (int, long)):
            expr = state.se.BVV(expr, state.arch.bits)

        return expr

    #
    # Helper functions
    #

    # Helper function to get an argument, given a list of register locations it can be and stack information for overflows.
    def arg_getter(self, state, reg_offsets, args_mem_base, index):
        stack_step = -state.arch.stack_change

        if index < len(reg_offsets):
            expr = state.registers.load(reg_offsets[index], endness=state.arch.register_endness)
        else:
            index -= len(reg_offsets)
            mem_addr = args_mem_base + (index * stack_step) + self.STACKARG_SP_BUFF
            expr = state.memory.load(mem_addr, stack_step, endness=state.arch.memory_endness)

        return expr

    def arg_setter(self, state, expr, reg_offsets, args_mem_base, index):
        stack_step = -state.arch.stack_change

        # Set register parameters
        if index < len(reg_offsets):
            offs = reg_offsets[index]
            state.registers.store(offs, expr, endness=state.arch.register_endness)

        # Set remaining parameters on the stack
        else:
            index -= len(reg_offsets)
            mem_addr = args_mem_base + (index * stack_step) + self.STACKARG_SP_BUFF
            state.memory.store(mem_addr, expr, endness=state.arch.memory_endness)

    @property
    def arguments(self):
        return self.args

    def __repr__(self):
        return "SimCC"

class SimCCCdecl(SimCC):
    ARG_REGS = [ ] # All arguments are passed in stack
    STACKARG_SP_DIFF = 4 # Return address is pushed on to stack by call
    RET_VAL_REG = 'eax'

    def set_return_addr(self, state, addr):
        state.stack_push(addr)

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchX86) and sp_delta == 0:
            any_reg_args = any([a for a in args if isinstance(a, SimRegArg)])

            if not any_reg_args:
                return True

        return False

class SimCCX86LinuxSyscall(SimCC):
    ARG_REGS = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
    STACKARG_SP_DIFF = 0
    RET_VAL_REG = 'eax'

    @staticmethod
    def _match(arch, args, sp_delta): # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

class SimCCSystemVAMD64(SimCC):
    ARG_REGS = [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9' ]
    STACKARG_SP_DIFF = 8 # Return address is pushed on to stack by call
    RET_VAL_REG = 'rax'

    def __init__(self, arch, args=None, ret_vals=None, sp_delta=None):
        SimCC.__init__(self, arch, args, ret_vals, sp_delta)

        # Remove the ret address on stack
        if self.args is not None:
            self.args = [ i for i in self.args if not (isinstance(i, SimStackArg) and i.offset == 0x0) ]

    def set_return_addr(self, state, addr):
        state.stack_push(addr)

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchAMD64) and sp_delta == 0:
            reg_args = [ i.name for i in args if isinstance(i, SimRegArg)]
            for r in SimCCSystemVAMD64.ARG_REGS:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # There is still something left.
                # Bad!
                return False

            stack_args = [ i.offset for i in args if isinstance(i, SimStackArg) ]
            if 0x0 not in stack_args:
                # Where is the return address?
                # TODO: Are we too strict about this?
                return False

            # That's it!
            return True

        return False

    def __repr__(self):
        return "System V AMD64 - %s %s" % (self.arch.name, self.args)

class SimCCAMD64LinuxSyscall(SimCC):
    ARG_REGS = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
    STACKARG_SP_DIFF = 0
    RET_VAL_REG = 'rax'

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

class SimCCARM(SimCC):
    ARG_REGS = [ 'r0', 'r1', 'r2', 'r3' ]
    STACKARG_SP_DIFF = 0
    RET_VAL_REG = 'r0'

    def set_return_addr(self, state, addr):
        state.regs.lr = addr

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchARM) and sp_delta == 0:
            reg_args = [ i.name for i in args if isinstance(i, SimRegArg) ]

            for r in SimCCARM.ARG_REGS:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # Still something left...
                return False

            return True

        return False

class SimCCAArch64(SimCC):
    ARG_REGS = [ 'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7' ]
    STACKARG_SP_DIFF = 0
    RET_VAL_REG = 'x0'

    def set_return_addr(self, state, addr):
        state.regs.lr = addr

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchAArch64) and sp_delta == 0:
            reg_args = [ i.name for i in args if isinstance(i, SimRegArg) ]

            for r in SimCCAArch64.ARG_REGS:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # Still something left...
                return False

            return True

        return False

class SimCCO32(SimCC):
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    STACKARG_SP_DIFF = 0
    STACKARG_SP_BUFF = 16
    RET_VAL_REG = 'v0'

    def set_return_addr(self, state, addr):
        state.regs.lr = addr

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchMIPS32) and sp_delta == 0:
            reg_args = [i.name for i in args if isinstance(i, SimRegArg)]

            for r in SimCCO32.ARG_REGS:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # Still something left...
                return False

            return True

        return False

class SimCCO64(SimCC):
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    STACKARG_SP_DIFF = 0
    STACKARG_SP_BUFF = 32
    RET_VAL_REG = 'v0'

    def set_return_addr(self, state, addr):
        state.regs.lr = addr

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchMIPS64) and sp_delta == 0:
            reg_args = [i.name for i in args if isinstance(i, SimRegArg)]

            for r in SimCCO64.ARG_REGS:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # Still something left...
                return False

            return True

        return False

class SimCCPowerPC(SimCC):
    ARG_REGS = [ 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10' ]
    STACKARG_SP_DIFF = 0
    STACKARG_SP_BUFF = 8
    RET_VAL_REG = 'r3'

    def set_return_addr(self, state, addr):
        state.regs.lr = addr

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchPPC32) and sp_delta == 0:
            reg_args = [i.name for i in args if isinstance(i, SimRegArg)]

            for r in SimCCPowerPC.ARG_REGS:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # Still something left...
                return False

            return True

        return False

class SimCCPowerPC64(SimCC):
    ARG_REGS = [ 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10' ]
    STACKARG_SP_DIFF = 0
    STACKARG_SP_BUFF = 0x70
    RET_VAL_REG = 'r3'

    def set_return_addr(self, state, addr):
        state.regs.lr = addr

    @staticmethod
    def _match(arch, args, sp_delta):
        if isinstance(arch, ArchPPC64) and sp_delta == 0:
            reg_args = [i.name for i in args if isinstance(i, SimRegArg)]

            for r in SimCCPowerPC64.ARG_REGS:
                if r in reg_args:
                    reg_args.remove(r)
            if reg_args:
                # Still something left...
                return False

            return True

        return False

class SimCCUnknown(SimCC):
    '''
    WOW an unknown calling convention!
    '''

    @staticmethod
    def _match(arch, args, sp_delta): # pylint: disable=unused-argument
        # It always returns True
        return True

    def __repr__(self):
        s = "UnknownCC - %s %s sp_delta=%d" % (self.arch.name, self.args, self.sp_delta)
        return s

CC = [ SimCCCdecl, SimCCSystemVAMD64, SimCCARM, SimCCO32, SimCCO64, SimCCPowerPC, SimCCPowerPC64, SimCCAArch64 ]
DefaultCC = {
    'AMD64': SimCCSystemVAMD64,
    'X86': SimCCCdecl,
    'ARMEL': SimCCARM,
    'ARMHF': SimCCARM,
    'MIPS32': SimCCO32,
    'MIPS64': SimCCO64,
    'PPC32': SimCCPowerPC,
    'PPC64': SimCCPowerPC64,
    'AARCH64': SimCCAArch64
}

# TODO: make OS-agnostic
SyscallCC = {
    'X86': SimCCX86LinuxSyscall,
    'AMD64': SimCCAMD64LinuxSyscall,
}

from .s_errors import SimCCError
