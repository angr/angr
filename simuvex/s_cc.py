import logging

import claripy
from archinfo import ArchX86, ArchAMD64, ArchARM, ArchAArch64, ArchMIPS32, ArchMIPS64, ArchPPC32, ArchPPC64

from . import s_type, s_action_object

l = logging.getLogger("simuvex.s_cc")

class PointerWrapper(object):
    def __init__(self, value):
        self.value = value


class AllocHelper(object):
    def __init__(self, ptr, grow_like_stack, reverse_result):
        self.ptr = ptr
        self.grow_like_stack = grow_like_stack
        self.reverse_result = reverse_result

    def dump(self, val, state, endness='Iend_BE'):
        if self.grow_like_stack:
            self.ptr -= val.length / 8
            state.memory.store(self.ptr, val, endness=endness)
            return self.ptr.reversed if self.reverse_result else self.ptr
        else:
            state.memory.store(self.ptr, val, endness=endness)
            out = self.ptr
            self.ptr += val.length / 8
            return out.reversed if self.reverse_result else out


class SimFunctionArgument(object):
    def __init__(self, size=None):
        self.size = size

    def __ne__(self, other):
        return not self == other

    def check_value(self, value):
        if not isinstance(value, claripy.ast.Base) and self.size is None:
            raise TypeError("Only claripy objects may be stored through SimFunctionArgument when size is not provided")
        if self.size is not None and isinstance(value, claripy.ast.Base) and self.size*8 != value.length:
            raise TypeError("%s doesn't fit in an argument of size %d" % (value, self.size))

    def set_value(self, state, value, **kwargs):
        raise NotImplementedError

    def get_value(self, state, **kwargs):
        raise NotImplementedError


class SimRegArg(SimFunctionArgument):
    def __init__(self, reg_offset, size=None):
        SimFunctionArgument.__init__(self, size)
        self.reg_offset = reg_offset

    def __repr__(self):
        return "<%s>" % self.reg_offset

    def __eq__(self, other):
        return type(other) is SimRegArg and self.reg_offset == other.reg_offset

    def set_value(self, state, value, endness=None, **kwargs):   # pylint: disable=unused-argument
        self.check_value(value)
        if endness is None: endness = state.arch.register_endness
        state.registers.store(self.reg_offset, value, endness=endness, size=self.size)

    def get_value(self, state, endness=None, **kwargs):          # pylint: disable=unused-argument
        if endness is None: endness = state.arch.register_endness
        return state.registers.load(self.reg_offset, endness=endness, size=self.size)


class SimStackArg(SimFunctionArgument):
    def __init__(self, stack_offset, size=None):
        SimFunctionArgument.__init__(self, size)
        self.stack_offset = stack_offset

    def __repr__(self):
        return "[%xh]" % self.stack_offset

    def __eq__(self, other):
        return type(other) is SimStackArg and self.stack_offset == other.stack_offset

    def set_value(self, state, value, endness=None, stack_base=None):    # pylint: disable=arguments-differ
        self.check_value(value)
        if endness is None: endness = state.arch.memory_endness
        if stack_base is None: stack_base = state.regs.sp
        state.memory.store(stack_base + self.stack_offset, value, endness=endness, size=self.size)

    def get_value(self, state, endness=None, stack_base=None):           # pylint: disable=arguments-differ
        if endness is None: endness = state.arch.memory_endness
        if stack_base is None: stack_base = state.regs.sp
        return state.memory.load(stack_base + self.stack_offset, endness=endness, size=self.size)


class ArgSession(object):
    '''
    A class to keep track of the state accumulated in laying parameters out into memory
    '''
    def __init__(self, cc):
        self.cc = cc
        self.real_args = None
        self.fp_iter = None
        self.int_iter = None
        self.both_iter = None

        if cc.args is None:
            self.fp_iter = cc.fp_args
            self.int_iter = cc.int_args
            self.both_iter = cc.both_args
        else:
            self.real_args = iter(cc.args)

    def next_arg(self, is_fp):
        if self.real_args is not None:
            try:
                arg = next(self.real_args)
                if is_fp and self.cc.is_fp_arg(arg) is False:
                    raise TypeError("Can't put a float here - concrete arg positions are specified")
                elif not is_fp and self.cc.is_fp_arg(arg) is True:
                    raise TypeError("Can't put an int here - concrete arg positions are specified")
            except StopIteration:
                raise TypeError("Accessed too many arguments - concrete number are specified")
        else:
            try:
                if is_fp:
                    return next(self.fp_iter)
                else:
                    return next(self.int_iter)
            except StopIteration:
                try:
                    return next(self.both_iter)
                except StopIteration:
                    raise TypeError("Accessed too many arguments - exhausted all positions?")


class SimCC(object):
    """
    This is the base class for all calling conventions.
    You should not directly instantiate this class.

    An instance of this class allows it to be tweaked to the way a specific function should be called.
    """
    def __init__(self, arch, args=None, ret_vals=None, sp_delta=None, func_ty=None):
        """
        :param arch:        The Archinfo arch for this binary
        :param args:        A list of SimFunctionArguments describing where the arguments go
        :param reg_vals:    A list of SimFunctionArguments describing where the return values go
        :param sp_delta:    The amount the stack pointer changes over the course of this function
        :parmm func_ty:     A SimType for the function itself
        """
        if func_ty is not None:
            if not isinstance(func_ty, s_type.SimTypeFunction):
                raise TypeError("Function prototype must be a function!")

        self.arch = arch
        self.args = args
        self.ret_vals = ret_vals
        self.sp_delta = sp_delta
        self.func_ty = func_ty

    #
    # Here are all the things a subclass needs to specify!
    #

    ARG_REGS = None                 # A list of all the registers used for integral args, in order (names or offsets)
    FP_ARG_REGS = None              # A list of all the registers used for floating point args, in order
    STACKARG_SP_BUFF = 0            # The amount of stack space reserved between the saved return address
                                    # (if applicable) and the arguments. Probably zero.
    STACKARG_SP_DIFF = 0            # The amount of stack space reserved for the return address
    return_addr = None              # The location where the return address is stored, as a SimFunctionArgument
    return_val = None               # The location where the return value is stored, as a SimFunctionArgument
    ARCH = None                     # The archinfo.Arch class that this CC must be used for, if relevant

    #
    # Here are several things you MAY want to override to change your cc's convention
    #

    @property
    def int_args(self):
        """
        Iterate through all the possible arg positions that can only be used to store integer or pointer values
        Does not take into account customizations.

        Returns an iterator of SimFunctionArguments
        """
        if self.ARG_REGS is None:
            raise NotImplementedError()
        for reg in self.ARG_REGS:            # pylint: disable=not-an-iterable
            yield SimRegArg(reg, self.arch.bytes)

    @property
    def both_args(self):
        """
        Iterate through all the possible arg positions that can be used to store any kind of argument
        Does not take into account customizations.

        Returns an iterator of SimFunctionArguments
        """
        turtle = self.STACKARG_SP_BUFF + self.STACKARG_SP_DIFF
        while True:
            yield SimStackArg(turtle, self.arch.bytes)
            turtle += self.arch.bytes

    @property
    def fp_args(self):
        """
        Iterate through all the possible arg positions that can only be used to store floating point values
        Does not take into account customizations.

        Returns an iterator of SimFunctionArguments
        """
        if self.FP_ARG_REGS is None:
            raise NotImplementedError()
        for reg in self.FP_ARG_REGS:        # pylint: disable=not-an-iterable
            yield SimRegArg(reg, self.arch.bytes)

    def is_fp_arg(self, arg):
        """
        This should take a SimFunctionArgument instance and return whether or not that argument is a floating-point
        argument.

        Returns True for MUST be a floating point arg,
                False for MUST NOT be a floating point arg,
                None for when it can be either.
        """
        if arg in self.int_args:
            return False
        if arg in self.fp_args:
            return True
        return None

    ArgSession = ArgSession     # import this from global scope so SimCC subclasses can subclass it if they like
    @property
    def arg_session(self):
        """
        Return an arg session.

        A session provides the control interface necessary to describe how integral and floating-point arguments are
        laid out into memory. The default behavior is that there are a finite list of int-only and fp-only argument
        slots, and an infinite number of generic slots, and when an argument of a given type is requested, the most
        slot available is used. If you need different behavior, subclass ArgSession.
        """
        return self.ArgSession(self)

    def stack_space(self, args):
        """
        :param args:        A list of SimFunctionArguments

        :returns:           The number of bytes that should be allocated on the stack to store all these args,
                            NOT INCLUDING the return address.
        """
        out = 0
        for arg in args:
            if isinstance(arg, SimStackArg):
                out = max(out, arg.stack_offset + self.arch.bytes)

        out += self.STACKARG_SP_BUFF
        return out

    #
    # Useful functions!
    #

    @staticmethod
    def is_fp_value(val):
        return isinstance(val, (float, claripy.ast.FP)) or \
                (isinstance(val, claripy.ast.Base) and val.op.startswith('fp')) or \
                (isinstance(val, claripy.ast.Base) and val.op == 'Reverse' and val.args[0].op.startswith('fp'))

    def arg_locs(self, is_fp):
        """
        Pass this a list of whether each parameter is floating-point or not, and get back a list of
        SimFunctionArguments.

        If you've customized this CC, this will sanity-check the provided locations with the given list.
        """
        session = self.arg_session
        return [session.next_arg(ifp) for ifp in is_fp]

    def arg(self, state, index, stack_base=None):
        """
        Returns a bitvector expression representing the nth argument of a function.

        `stack_base` is an optional pointer to the top of the stack at the function start. If it is not
        specified, use the current stack pointer.

        WARNING: this assumes that none of the arguments are floating-point, unless you've customized this CC.
        """
        session = self.arg_session
        if self.args is None:
            arg_loc = [session.next_arg(False) for _ in xrange(index + 1)][-1]
        else:
            arg_loc = self.args[index]

        return arg_loc.get_value(state, stack_base=stack_base)

    def get_args(self, state, is_fp=None, stack_base=None):
        """
        `is_fp` should be a list of booleans specifying whether each corresponding argument is floating-point -
        True for fp and False for int. For a shorthand to assume that all the parameters are int, pass the number of
        parameters as an int.

        If you've customized this CC, you may omit this parameter entirely. If it is provided, it is used for
        sanity-checking.

        `stack_base` is an optional pointer to the top of the stack at the function start. If it is not
        specified, use the current stack pointer.

        Returns a list of bitvector expressions representing the arguments of a function.
        """
        if is_fp is None:
            if self.args is None:
                raise ValueError("You must either customize this CC or pass a value to is_fp!")
            else:
                arg_locs = self.args
        elif type(is_fp) is int:
            if self.args is not None and len(self.args) != is_fp:
                raise ValueError("Bad number of args requested: got %d, expected %d" % (is_fp, len(self.args)))
            arg_locs = self.arg_locs([False]*is_fp)
        else:
            arg_locs = self.arg_locs(is_fp)

        return [loc.get_value(state, stack_base=stack_base) for loc in arg_locs]

    def setup_callsite(self, state, ret_addr, args, stack_base=None, alloc_base=None, grow_like_stack=True):
        """
        Okay. this one is serious.

        :param state:           The SimState to operate on
        :param ret_addr:        The address to return to when the called function finishes
        :param args:            The list of arguments that that the called function will see
        :param stack_base:      An optional pointer to use as the top of the stack, circa the function entry point
        :param alloc_base:      An optional pointer to use as the place to put excess argument data
        :param grow_like_stack: When allocating data at alloc_base, whether to allocate at decreasing addresses

        The idea here is that you can provide almost any kind of python type in `args` and it'll be translated to a
        binary format to be placed into simulated memory. Lists (representing arrays) must be entirely elements of the
        same type and size, while tuples (representing structs) can be elements of any type and size.
        If you'd like there to be a pointer to a given value, wrap the value in a `PointerWrapper`. Any value
        that can't fit in a register will be automatically put in a
        PointerWrapper.

        If stack_base is not provided, the current stack pointer will be used, and it will be updated.
        If alloc_base is not provided, the current stack pointer will be used, and it will be updated.
        You might not like the results if you provide stack_base but not alloc_base.

        grow_like_stack controls the behavior of allocating data at alloc_base. When data from args needs to be wrapped
        in a pointer, the pointer needs to point somewhere, so that data is dumped into memory at alloc_base. If you
        set alloc_base to point to somewhere other than the stack, set grow_like_stack to False so that sequencial
        allocations happen at increasing addresses.
        """
        arg_locs = self.arg_locs(map(self.is_fp_value, args))
        allocator = AllocHelper(alloc_base if alloc_base is not None else state.regs.sp,
                grow_like_stack,
                self.arch.memory_endness == 'Iend_LE')

        if self.func_ty is not None:
            vals = [self._standardize_value(arg, ty, state, allocator.dump) for arg, ty in zip(args, self.func_ty.args)]
        else:
            vals = [self._standardize_value(arg, None, state, allocator.dump) for arg in args]

        for i, val in enumerate(vals):
            if val.length > state.arch.bits:
                vals[i] = allocator.dump(val, state)
            elif val.length < state.arch.bits:
                if self.arch.memory_endness == 'Iend_LE':
                    vals[i] = val.concat(claripy.BVV(0, state.arch.bits - val.length))
                else:
                    vals[i] = claripy.BVV(0, state.arch.bits - val.length).concat(val)

        if alloc_base is None:
            state.regs.sp = allocator.ptr

        if stack_base is None:
            state.regs.sp -= self.stack_space(arg_locs) + self.STACKARG_SP_DIFF

        for loc, val in zip(arg_locs, vals):
            loc.set_value(state, val, endness='Iend_BE', stack_base=stack_base)
        self.return_addr.set_value(state, ret_addr, stack_base=stack_base)

    #
    # Helper functions
    #

    @staticmethod
    def _standardize_value(arg, ty, state, alloc):
        check = ty is not None
        if isinstance(arg, s_action_object.SimActionObject):
            return SimCC._standardize_value(arg.ast, ty, state, alloc)
        elif isinstance(arg, PointerWrapper):
            if check and not isinstance(ty, s_type.SimTypePointer):
                raise TypeError("Type mismatch: expected {}, got pointer-wrapper".format(ty))

            real_value = SimCC._standardize_value(arg.value, ty.pts_to if check else None, state, alloc)
            return alloc(real_value, state)

        elif isinstance(arg, str):
            # TODO: when we switch to py3, distinguish between str and bytes
            # by null-terminating str but not bytes :/
            arg += '\0'
            ref = False
            if check:
                if isinstance(ty, s_type.SimTypePointer) and \
                        isinstance(ty.pts_to, s_type.SimTypeChar):
                    ref = True
                elif isinstance(ty, s_type.SimTypeFixedSizeArray) and \
                        isinstance(ty.elem_type, s_type.SimTypeChar):
                    ref = False
                    if len(arg) > ty.length:
                        raise TypeError("String {} is too long for {}".format(repr(arg), ty))
                    arg = arg.ljust(ty.length, '\0')
                elif isinstance(ty, s_type.SimTypeArray) and \
                        isinstance(ty.elem_type, s_type.SimTypeChar):
                    ref = True
                    if ty.length is not None:
                        if len(arg) > ty.length:
                            raise TypeError("String {} is too long for {}".format(repr(arg), ty))
                        arg = arg.ljust(ty.length, '\0')
                elif isinstance(ty, s_type.SimTypeString):
                    ref = False
                    if len(arg) > ty.length + 1:
                        raise TypeError("String {} is too long for {}".format(repr(arg), ty))
                    arg = arg.ljust(ty.length + 1, '\0')
                else:
                    raise TypeError("Type mismatch: Expected {}, got char*".format(ty))
            val = SimCC._standardize_value(map(ord, arg), s_type.SimTypeFixedSizeArray(s_type.SimTypeChar(), len(arg)), state, alloc)
            if ref:
                val = alloc(val, state)
            return val

        elif isinstance(arg, list):
            ref = False
            subty = None
            if check:
                if isinstance(ty, s_type.SimTypePointer):
                    ref = True
                    subty = ty.pts_to
                elif isinstance(ty, s_type.SimTypeFixedSizeArray):
                    ref = False
                    subty = ty.elem_type
                    if len(arg) != ty.length:
                        raise TypeError("Array {} is the wrong length for {}".format(repr(arg), ty))
                elif isinstance(ty, s_type.SimTypeArray):
                    ref = True
                    subty = ty.elem_type
                    if ty.length is not None:
                        if len(arg) != ty.length:
                            raise TypeError("Array {} is the wrong length for {}".format(repr(arg), ty))
                else:
                    raise TypeError("Type mismatch: Expected {}, got char*".format(ty))
            else:
                types = map(type, arg)
                if types[1:] != types[:-1]:
                    raise TypeError("All elements of list must be of same type")

            val = claripy.Concat(*[SimCC._standardize_value(sarg, subty, state, alloc) for sarg in arg])
            if ref:
                val = alloc(val, state)
            return val

        elif isinstance(arg, tuple):
            if check:
                if not isinstance(ty, s_type.SimStruct):
                    raise TypeError("Type mismatch: Expected {}, got tuple (i.e. struct)".format(ty))
                if len(arg) != len(ty.fields):
                    raise TypeError("Wrong number of fields in struct, expected {} got {}".format(len(ty.fields), len(arg)))
                return claripy.Concat(*[SimCC._standardize_value(sarg, sty, state, alloc)
                                        for sarg, sty
                                        in zip(arg, ty.fields.values())])
            else:
                return claripy.Concat(*[SimCC._standardize_value(sarg, None, state, alloc) for sarg in arg])

        elif isinstance(arg, (int, long)):
            val = state.se.BVV(arg, ty.size if check else state.arch.bits)
            if state.arch.memory_endness == 'Iend_LE':
                val = val.reversed
            return val

        elif isinstance(arg, float):
            # TODO: type checking, no SimTypeFloat exists rn
            sort = claripy.FSORT_DOUBLE if state.arch.bits == 64 else claripy.FSORT_FLOAT
            val = claripy.fpToIEEEBV(claripy.FPV(arg, sort))
            if state.arch.memory_endness == 'Iend_LE':
                val = val.reversed      # pylint: disable=no-member
            return val

        elif isinstance(arg, claripy.ast.Base):
            # yikes
            if state.arch.memory_endness == 'Iend_LE' and arg.length == state.arch.bits:
                arg = arg.reversed
            return arg

        else:
            raise TypeError("I don't know how to put %s onto the stack." % repr(arg))

    def __repr__(self):
        return "<" + self.__class__.__name__ + '>'

    @classmethod
    def _match(cls, arch, args, sp_delta):
        if cls.ARCH is not None and not isinstance(arch, cls.ARCH):
            return False
        if sp_delta != cls.STACKARG_SP_DIFF:
            return False

        sample_inst = cls(arch)
        all_fp_args = list(sample_inst.fp_args)
        all_int_args = list(sample_inst.int_args)
        both_iter = sample_inst.both_args
        some_both_args = [next(both_iter) for _ in xrange(len(args))]

        for arg in args:
            if arg not in all_fp_args and arg not in all_int_args and arg not in some_both_args:
                return False

        return True


class SimCCCdecl(SimCC):
    ARG_REGS = [] # All arguments are passed in stack
    FP_ARG_REGS = ['st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7']
    STACKARG_SP_DIFF = 4 # Return address is pushed on to stack by call
    return_val = SimRegArg('eax', 4)
    return_addr = SimStackArg(0, 4)
    ARCH = ArchX86

class SimCCX86LinuxSyscall(SimCC):
    ARG_REGS = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
    FP_ARG_REGS = []
    return_val = SimRegArg('eax', 4)
    ARCH = ArchX86

    @classmethod
    def _match(cls, arch, args, sp_delta): # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

class SimCCSystemVAMD64(SimCC):
    ARG_REGS = [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9' ]
    FP_ARG_REGS = []    # TODO: xmm regs for fp passing
    STACKARG_SP_DIFF = 8 # Return address is pushed on to stack by call
    return_addr = SimStackArg(0, 8)
    return_val = SimRegArg('rax', 8)
    ARCH = ArchAMD64

    def __init__(self, arch, args=None, ret_vals=None, sp_delta=None, func_ty=None):
        super(SimCCSystemVAMD64, self).__init__(arch, args, ret_vals, sp_delta, func_ty)

        # Remove the ret address on stack
        if self.args is not None:
            self.args = [ i for i in self.args if not (isinstance(i, SimStackArg) and i.stack_offset == 0x0) ]

    @classmethod
    def _match(cls, arch, args, sp_delta):
        if cls.ARCH is not None and not isinstance(arch, cls.ARCH):
            return False
        #if sp_delta != cls.STACKARG_SP_DIFF:
        #    return False

        sample_inst = cls(arch)
        all_fp_args = list(sample_inst.fp_args)
        all_int_args = list(sample_inst.int_args)
        both_iter = sample_inst.both_args
        some_both_args = [next(both_iter) for _ in xrange(len(args))]

        for arg in args:
            if arg not in all_fp_args and arg not in all_int_args and arg not in some_both_args:
                if isinstance(arg, SimStackArg) and arg.stack_offset == 0:
                    continue        # ignore return address?
                return False

        return True

class SimCCAMD64LinuxSyscall(SimCC):
    ARG_REGS = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
    return_val = SimRegArg('rax', 8)
    ARCH = ArchAMD64

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

class SimCCARM(SimCC):
    ARG_REGS = [ 'r0', 'r1', 'r2', 'r3' ]
    FP_ARG_REGS = []    # TODO: ???
    return_addr = SimRegArg('lr', 4)
    return_val = SimRegArg('r0', 4)
    ARCH = ArchARM

class SimCCAArch64(SimCC):
    ARG_REGS = [ 'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7' ]
    FP_ARG_REGS = []    # TODO: ???
    return_addr = SimRegArg('lr', 8)
    return_val = SimRegArg('x0', 8)
    ARCH = ArchAArch64

class SimCCO32(SimCC):
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 16
    return_addr = SimRegArg('lr', 4)
    return_val = SimRegArg('v0', 4)
    ARCH = ArchMIPS32

class SimCCO64(SimCC):      # TODO: this calling convention doesn't actually exist???? there's o32, n32, and n64
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 32
    return_addr = SimRegArg('lr', 8)
    return_val = SimRegArg('v0', 8)
    ARCH = ArchMIPS64

class SimCCPowerPC(SimCC):
    ARG_REGS = [ 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 8
    return_addr = SimRegArg('lr', 4)
    return_val = SimRegArg('r3', 4)
    ARCH = ArchPPC32

class SimCCPowerPC64(SimCC):
    ARG_REGS = [ 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 0x70
    return_addr = SimRegArg('lr', 8)
    return_val = SimRegArg('r3', 8)
    ARCH = ArchPPC64

class SimCCUnknown(SimCC):
    """
    Represent an unknown calling convention.
    """
    @staticmethod
    def _match(arch, args, sp_delta): # pylint: disable=unused-argument
        # It always returns True
        return True

    def __repr__(self):
        return "<SimCCUnknown - %s %s sp_delta=%d>" % (self.arch.name, self.args, self.sp_delta)

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
