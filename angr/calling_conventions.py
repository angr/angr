import logging

import claripy
import archinfo
from archinfo import RegisterName
from typing import Union, Optional, List, Dict

from .sim_type import SimType
from .sim_type import SimTypeChar
from .sim_type import SimTypePointer
from .sim_type import SimTypeFixedSizeArray
from .sim_type import SimTypeArray
from .sim_type import SimTypeString
from .sim_type import SimTypeFunction
from .sim_type import SimTypeFloat
from .sim_type import SimTypeDouble
from .sim_type import SimTypeReg
from .sim_type import SimStruct
from .sim_type import parse_file
from .sim_type import SimTypeTop

from .state_plugins.sim_action_object import SimActionObject

l = logging.getLogger(name=__name__)
from .engines.soot.engine import SootMixin

# TODO: This file contains explicit and implicit byte size assumptions all over. A good attempt to fix them was made.
# If your architecture hails from the astral plane, and you're reading this, start fixing here.


class PointerWrapper:
    def __init__(self, value):
        self.value = value


class AllocHelper:
    def __init__(self, ptrsize, reverse_result):
        self.base = claripy.BVS('alloc_base', ptrsize)
        self.ptr = self.base
        self.reverse_result = reverse_result
        self.stores = {}

    def dump(self, val, state, endness='Iend_BE'):
        self.stores[self.ptr.cache_key] = (val, endness)
        out = self.ptr
        self.ptr += val.length // state.arch.byte_width
        return out.reversed if self.reverse_result else out

    def translate(self, val, base):
        return val.replace(self.base, base)

    def apply(self, state, base):
        for ptr, (val, endness) in self.stores.items():
            state.memory.store(self.translate(ptr.ast, base), self.translate(val, base), endness=endness)

    def size(self):
        val = self.translate(self.ptr, claripy.BVV(0, len(self.ptr)))
        assert val.op == 'BVV'
        return abs(val.args[0])


class SimFunctionArgument:
    """
    Represent a generic function argument.

    :ivar int size:    The size of the argument, in number of bytes.
    """
    def __init__(self, size):
        self.size = size

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(('function_argument', self.size))

    def check_value(self, value):
        if not isinstance(value, claripy.ast.Base) and self.size is None:
            raise TypeError("Only claripy objects may be stored through SimFunctionArgument when size is not provided")
        if self.size is not None and isinstance(value, claripy.ast.Base) and self.size*8 < value.length:
            raise TypeError("%s doesn't fit in an argument of size %d" % (value, self.size))

    def set_value(self, state, value, **kwargs):
        raise NotImplementedError

    def get_value(self, state, **kwargs):
        raise NotImplementedError


class SimRegArg(SimFunctionArgument):
    """
    Represents a function argument that has been passed in a register.

    :ivar string reg_name:    The name of the represented register.
    :ivar int size:           The size of the register, in number of bytes.
    """
    def __init__(self, reg_name: RegisterName, size: int, alt_offsets=None):
        SimFunctionArgument.__init__(self, size)
        self.reg_name = reg_name
        self.alt_offsets = {} if alt_offsets is None else alt_offsets

    def __repr__(self):
        return "<%s>" % self.reg_name

    def __eq__(self, other):
        return type(other) is SimRegArg and self.reg_name == other.reg_name

    def __hash__(self):
        return hash((self.size, self.reg_name, tuple(self.alt_offsets)))

    def _fix_offset(self, state, size, arch=None):
        """
        This is a hack to deal with small values being stored at offsets into large registers unpredictably
        """
        if state is not None:
            arch = state.arch

        if arch is None:
            raise ValueError('Either "state" or "arch" must be specified.')

        offset = arch.registers[self.reg_name][0]
        if size in self.alt_offsets:
            return offset + self.alt_offsets[size]
        elif size < self.size and arch.register_endness == 'Iend_BE':
            return offset + (self.size - size)
        return offset

    def set_value(self, state, value, endness=None, size=None, **kwargs):  # pylint: disable=unused-argument,arguments-differ
        self.check_value(value)
        if endness is None: endness = state.arch.register_endness
        if isinstance(value, int): value = claripy.BVV(value, self.size*8)
        if size is None: size = min(self.size, value.length // 8)
        offset = self._fix_offset(state, size)
        state.registers.store(offset, value, endness=endness, size=size)

    def get_value(self, state, endness=None, size=None, **kwargs):  # pylint: disable=unused-argument,arguments-differ
        if endness is None: endness = state.arch.register_endness
        if size is None: size = self.size
        offset = self._fix_offset(state, size)
        return state.registers.load(offset, endness=endness, size=size)


class SimStackArg(SimFunctionArgument):
    """
    Represents a function argument that has been passed on the stack.

    :var int stack_offset:    The position of the argument relative to the stack pointer after the function prelude.
    :ivar int size:           The size of the argument, in number of bytes.
    """
    def __init__(self, stack_offset, size):
        SimFunctionArgument.__init__(self, size)
        self.stack_offset = stack_offset

    def __repr__(self):
        return "[%#x]" % self.stack_offset

    def __eq__(self, other):
        return type(other) is SimStackArg and self.stack_offset == other.stack_offset

    def __hash__(self):
        return hash((self.size, self.stack_offset))

    def set_value(self, state, value, endness=None, stack_base=None):  # pylint: disable=arguments-differ
        self.check_value(value)
        if endness is None: endness = state.arch.memory_endness
        if stack_base is None: stack_base = state.regs.sp
        if isinstance(value, int): value = claripy.BVV(value, self.size*8)
        state.memory.store(stack_base + self.stack_offset, value, endness=endness, size=value.length//8)

    def get_value(self, state, endness=None, stack_base=None, size=None):  # pylint: disable=arguments-differ
        if endness is None: endness = state.arch.memory_endness
        if stack_base is None: stack_base = state.regs.sp
        return state.memory.load(stack_base + self.stack_offset, endness=endness, size=size or self.size)


class SimComboArg(SimFunctionArgument):
    def __init__(self, locations):
        super(SimComboArg, self).__init__(sum(x.size for x in locations))
        self.locations = locations

    def __repr__(self):
        return 'SimComboArg(%s)' % repr(self.locations)

    def __eq__(self, other):
        return type(other) is SimComboArg and all(a == b for a, b in zip(self.locations, other.locations))

    def set_value(self, state, value, endness=None, **kwargs):  # pylint:disable=arguments-differ
        # TODO: This code needs to be reworked for variable byte width and the Third Endness
        self.check_value(value)
        if endness is None: endness = state.arch.memory_endness
        if isinstance(value, int):
            value = claripy.BVV(value, self.size*state.arch.byte_width)
        elif isinstance(value, float):
            if self.size not in (4, 8):
                raise ValueError("What do I do with a float %d bytes long" % self.size)
            value = claripy.FPV(value, claripy.FSORT_FLOAT if self.size == 4 else claripy.FSORT_DOUBLE)
        cur = 0
        # TODO: I have no idea if this reversed is only supposed to be applied in LE situations
        for loc in reversed(self.locations):
            loc.set_value(state, value[cur*state.arch.byte_width + loc.size*state.arch.byte_width - 1:cur*state.arch.byte_width], endness=endness, **kwargs)
            cur += loc.size

    def get_value(self, state, endness=None, **kwargs):  # pylint:disable=arguments-differ
        if endness is None: endness = state.arch.memory_endness
        vals = []
        for loc in reversed(self.locations):
            vals.append(loc.get_value(state, endness, **kwargs))
        return state.solver.Concat(*vals)


class ArgSession:
    """
    A class to keep track of the state accumulated in laying parameters out into memory
    """

    __slots__ = ('cc', 'real_args', 'fp_iter', 'int_iter', 'both_iter', )

    def __init__(self, cc):
        self.cc = cc
        self.real_args = None
        self.fp_iter = None
        self.int_iter = None
        self.both_iter = None

        # these iters should only be used if real_args are not set or real_args are intentionally ignored (e.g., when
        # variadic arguments are used).
        self.fp_iter = cc.fp_args
        self.int_iter = cc.int_args
        self.both_iter = cc.both_args

        if cc.args is not None:
            self.real_args = iter(cc.args)

    # TODO: use safer errors than TypeError and ValueError
    def next_arg(self, is_fp, size=None, ignore_real_args=False):
        if self.real_args is not None and not ignore_real_args:
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
                    arg = next(self.fp_iter)
                else:
                    arg = next(self.int_iter)
            except StopIteration:
                try:
                    arg = next(self.both_iter)
                except StopIteration:
                    raise TypeError("Accessed too many arguments - exhausted all positions?")

        if size is not None and size > arg.size:
            arg = self.upsize_arg(arg, is_fp, size)
        return arg

    def upsize_arg(self, arg, is_fp, size):
        if not is_fp:
            raise ValueError("You can't fit a integral value of size %d into an argument of size %d!" % (size, arg.size))
        if not isinstance(arg, SimStackArg):
            raise ValueError("I don't know how to handle this? please report to @rhelmot")

        arg_size = arg.size
        locations = [arg]
        while arg_size < size:
            next_arg = self.next_arg(is_fp, None)
            arg_size += next_arg.size
            locations.append(next_arg)

        return SimComboArg(locations)


class SimCC:
    """
    A calling convention allows you to extract from a state the data passed from function to
    function by calls and returns. Most of the methods provided by SimCC that operate on a state
    assume that the program is just after a call but just before stack frame allocation, though
    this may be overridden with the `stack_base` parameter to each individual method.

    This is the base class for all calling conventions.

    An instance of this class allows it to be tweaked to the way a specific function should be called.
    """
    def __init__(self,
            arch: archinfo.Arch,
            args: Optional[List[SimFunctionArgument]]=None,
            ret_val: Optional[SimFunctionArgument]=None,
            sp_delta: Optional[int]=None,
            func_ty: Optional[Union[SimTypeFunction, str]]=None):
        """
        :param arch:        The Archinfo arch for this CC
        :param args:        A list of SimFunctionArguments describing where the arguments go
        :param ret_val:     A SimFunctionArgument describing where the return value goes
        :param sp_delta:    The amount the stack pointer changes over the course of this function - CURRENTLY UNUSED
        :param func_ty:     A SimTypeFunction for the function itself, or a string that can be parsed into a
                            SimTypeFunction instance.

        Example func_ty strings:
        >>> "int func(char*, int)"
        >>> "int f(int, int, int*);"
        Function names are ignored.

        """
        if func_ty is not None:
            if isinstance(func_ty, str):
                if not func_ty.endswith(";"):
                    func_ty += ";"  # Make pycparser happy
                parsed = parse_file(func_ty)
                parsed_decl = parsed[0]
                if not parsed_decl:
                    raise ValueError('Cannot parse the provided function prototype.')
                _, func_ty = next(iter(parsed_decl.items()))

            if not isinstance(func_ty, SimTypeFunction):
                raise TypeError("Function prototype must be a SimTypeFunction instance or a string that can be parsed "
                                "into a SimTypeFunction instance.")

        self.arch = arch
        self.args = args
        self.ret_val = ret_val
        self.sp_delta = sp_delta
        self.func_ty: Optional[SimTypeFunction] = func_ty if func_ty is None else func_ty.with_arch(arch)

    @classmethod
    def from_arg_kinds(cls, arch, fp_args, ret_fp=False, sizes=None, sp_delta=None, func_ty=None):
        """
        Get an instance of the class that will extract floating-point/integral args correctly.

        :param arch:        The Archinfo arch for this CC
        :param fp_args:     A list, with one entry for each argument the function can take. True if the argument is fp,
                            false if it is integral.
        :param ret_fp:      True if the return value for the function is fp.
        :param sizes:       Optional: A list, with one entry for each argument the function can take. Each entry is the
                            size of the corresponding argument in bytes.
        :param sp_delta:    The amount the stack pointer changes over the course of this function - CURRENTLY UNUSED
        :parmm func_ty:     A SimType for the function itself
        """
        basic = cls(arch, sp_delta=sp_delta, func_ty=func_ty)
        basic.args = basic.arg_locs(fp_args, sizes)
        basic.ret_val = basic.fp_return_val if ret_fp else basic.return_val
        return basic

    #
    # Here are all the things a subclass needs to specify!
    #

    ARG_REGS: List[str] = None                                  # A list of all the registers used for integral args, in order (names or offsets)
    FP_ARG_REGS: List[str] = None                               # A list of all the registers used for floating point args, in order
    STACKARG_SP_BUFF = 0                                        # The amount of stack space reserved between the saved return address
                                                                # (if applicable) and the arguments. Probably zero.
    STACKARG_SP_DIFF = 0                                        # The amount of stack space reserved for the return address
    CALLER_SAVED_REGS: List[str] = None                         # Caller-saved registers
    RETURN_ADDR: SimFunctionArgument = None                     # The location where the return address is stored, as a SimFunctionArgument
    RETURN_VAL: SimFunctionArgument = None                      # The location where the return value is stored, as a SimFunctionArgument
    OVERFLOW_RETURN_VAL: Optional[SimFunctionArgument] = None   # The second half of the location where a double-length return value is stored
    FP_RETURN_VAL: Optional[SimFunctionArgument] = None         # The location where floating-point argument return values are stored
    ARCH = None                                                 # The archinfo.Arch class that this CC must be used for, if relevant
    CALLEE_CLEANUP = False                                      # Whether the callee has to deallocate the stack space for the arguments

    STACK_ALIGNMENT = 1             # the alignment requirement of the stack pointer at function start BEFORE call

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
            yield SimRegArg(reg, self.arch.registers[reg][1])

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
        if arg in self.fp_args or arg == self.FP_RETURN_VAL:
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
        out = self.STACKARG_SP_DIFF
        for arg in args:
            if isinstance(arg, SimStackArg):
                out = max(out, arg.stack_offset + self.arch.bytes)

        out += self.STACKARG_SP_BUFF
        return out

    @property
    def return_val(self):
        """
        The location the return value is stored.
        """
        # pylint: disable=unsubscriptable-object
        if self.ret_val is not None:
            return self.ret_val

        if self.func_ty is not None and \
                self.func_ty.returnty is not None and \
                self.OVERFLOW_RETURN_VAL is not None and \
                self.func_ty.returnty.size not in (None, NotImplemented) and \
                self.func_ty.returnty.size > self.RETURN_VAL.size * self.arch.byte_width:
            return SimComboArg([self.RETURN_VAL, self.OVERFLOW_RETURN_VAL])
        return self.RETURN_VAL

    @property
    def fp_return_val(self):
        return self.FP_RETURN_VAL if self.ret_val is None else self.ret_val

    @property
    def return_addr(self):
        """
        The location the return address is stored.
        """
        return self.RETURN_ADDR

    #
    # Useful functions!
    #

    @staticmethod
    def is_fp_value(val):
        return isinstance(val, (float, claripy.ast.FP)) or \
                (isinstance(val, claripy.ast.Base) and val.op.startswith('fp')) or \
                (isinstance(val, claripy.ast.Base) and val.op == 'Reverse' and val.args[0].op.startswith('fp'))

    def arg_locs(self, is_fp=None, sizes=None):
        """
        Pass this a list of whether each parameter is floating-point or not, and get back a list of
        SimFunctionArguments. Optionally, pass a list of argument sizes (in bytes) as well.

        If you've customized this CC, this will sanity-check the provided locations with the given list.
        """
        session = self.arg_session
        if self.func_ty is None and self.args is None:
            # No function prototype is provided, no args is provided. `is_fp` must be provided.
            if is_fp is None:
                raise ValueError('"is_fp" must be provided when no function prototype is available.')
        else:
            # let's rely on the func_ty or self.args for the number of arguments and whether each argument is FP or not
            if self.func_ty is not None:
                args = [ a.with_arch(self.arch) for a in self.func_ty.args ]
            else:
                args = self.args
            is_fp = [ True if isinstance(arg, (SimTypeFloat, SimTypeDouble)) or self.is_fp_arg(arg) else False
                      for arg in args ]
            if sizes is None:
                # initialize sizes from args
                sizes = [ ]
                for a in args:
                    if isinstance(a, SimType):
                        if a.size is NotImplemented:
                            sizes.append(self.arch.bytes)
                        else:
                            sizes.append(a.size // 8)  # SimType.size is in bits
                    elif isinstance(a, SimFunctionArgument):
                        sizes.append(a.size)  # SimFunctionArgument.size is in bytes
                    else:
                        # fallback to use self.arch.bytes
                        sizes.append(self.arch.bytes)

        if sizes is None: sizes = [self.arch.bytes] * len(is_fp)
        return [session.next_arg(ifp, size=sz) for ifp, sz in zip(is_fp, sizes)]

    def arg(self, state, index, stack_base=None):
        """
        Returns a bitvector expression representing the nth argument of a function.

        `stack_base` is an optional pointer to the top of the stack at the function start. If it is not
        specified, use the current stack pointer.

        WARNING: this assumes that none of the arguments are floating-point and they're all single-word-sized, unless
        you've customized this CC.
        """
        session = self.arg_session
        if self.args is None or index >= len(self.args):
            # self.args may not be provided, or args is incorrect or includes variadic arguments that we must get the
            # proper argument according to the default calling convention
            arg_loc = [session.next_arg(False, ignore_real_args=True) for _ in range(index + 1)][-1]
        else:
            arg_loc = self.args[index]

        return arg_loc.get_value(state, stack_base=stack_base)

    def get_args(self, state, is_fp=None, sizes=None, stack_base=None):
        """
        `is_fp` should be a list of booleans specifying whether each corresponding argument is floating-point -
        True for fp and False for int. For a shorthand to assume that all the parameters are int, pass the number of
        parameters as an int.

        If you've customized this CC, you may omit this parameter entirely. If it is provided, it is used for
        sanity-checking.

        `sizes` is an optional list of argument sizes, in bytes. Be careful about using this if you've made explicit
        the arg locations, since it might decide to combine two locations into one if an arg is too big.

        `stack_base` is an optional pointer to the top of the stack at the function start. If it is not
        specified, use the current stack pointer.

        Returns a list of bitvector expressions representing the arguments of a function.
        """
        if sizes is None and self.func_ty is not None:
            sizes = [arg.size for arg in self.func_ty.args]
        if is_fp is None:
            if self.args is None:
                if self.func_ty is None:
                    raise ValueError("You must either customize this CC or pass a value to is_fp!")
                else:
                    arg_locs = self.arg_locs([False]*len(self.func_ty.args))
            else:
                arg_locs = self.args

        elif type(is_fp) is int:
            if self.args is not None and len(self.args) != is_fp:
                raise ValueError("Bad number of args requested: got %d, expected %d" % (is_fp, len(self.args)))
            arg_locs = self.arg_locs([False]*is_fp, sizes)
        else:
            arg_locs = self.arg_locs(is_fp, sizes)

        return [loc.get_value(state, stack_base=stack_base) for loc in arg_locs]

    def setup_callsite(self, state, ret_addr, args, stack_base=None, alloc_base=None, grow_like_stack=True):
        """
        This function performs the actions of the caller getting ready to jump into a function.

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
        that can't fit in a register will be automatically put in a PointerWrapper.

        If stack_base is not provided, the current stack pointer will be used, and it will be updated.
        If alloc_base is not provided, the stack base will be used and grow_like_stack will implicitly be True.

        grow_like_stack controls the behavior of allocating data at alloc_base. When data from args needs to be wrapped
        in a pointer, the pointer needs to point somewhere, so that data is dumped into memory at alloc_base. If you
        set alloc_base to point to somewhere other than the stack, set grow_like_stack to False so that sequential
        allocations happen at increasing addresses.
        """

        # STEP 0: clerical work

        if isinstance(self, SimCCSoot):
            SootMixin.setup_callsite(state, args, ret_addr)
            return

        allocator = AllocHelper(self.arch.bits, self.arch.memory_endness == 'Iend_LE')

        #
        # STEP 1: convert all values into serialized form
        # this entails creating the vals list of simple values to store and also populating the allocator's
        # understanding of what aux data needs to be stored
        # This is also where we compute arg locations (arg_locs)
        #

        if self.func_ty is not None:
            vals = [self._standardize_value(arg, ty, state, allocator.dump) for arg, ty in zip(args, self.func_ty.args)]
        else:
            vals = [self._standardize_value(arg, None, state, allocator.dump) for arg in args]

        arg_session = self.arg_session
        arg_locs = [None]*len(args)
        for i, (arg, val) in enumerate(zip(args, vals)):
            if self.is_fp_value(arg) or \
                    (self.func_ty is not None and isinstance(self.func_ty.args[i], SimTypeFloat)):
                arg_locs[i] = arg_session.next_arg(is_fp=True, size=val.length // state.arch.byte_width)
                continue
            if val.length > state.arch.bits or (self.func_ty is None and isinstance(arg, (bytes, str, list, tuple))):
                vals[i] = allocator.dump(val, state)
            elif val.length < state.arch.bits:
                if self.arch.memory_endness == 'Iend_LE':
                    vals[i] = val.concat(claripy.BVV(0, state.arch.bits - val.length))
                else:
                    vals[i] = claripy.BVV(0, state.arch.bits - val.length).concat(val)
            arg_locs[i] = arg_session.next_arg(is_fp=False, size=vals[i].length // state.arch.byte_width)

        #
        # STEP 2: decide on memory storage locations
        # implement the contract for stack_base/alloc_base/grow_like_stack
        # after this, stack_base should be the final stack pointer, alloc_base should be the final aux storage location,
        # and the stack pointer should be updated
        #

        if stack_base is None:
            if alloc_base is None:
                alloc_size = allocator.size()
                state.regs.sp -= alloc_size
                alloc_base = state.regs.sp
                grow_like_stack = False

            state.regs.sp -= self.stack_space(arg_locs)

            # handle alignment
            alignment = (state.regs.sp + self.STACKARG_SP_DIFF) % self.STACK_ALIGNMENT
            state.regs.sp -= alignment

        else:
            state.regs.sp = stack_base

            if alloc_base is None:
                alloc_base = stack_base + self.stack_space(arg_locs)
                grow_like_stack = False

        if grow_like_stack:
            alloc_base -= allocator.size()
        if type(alloc_base) is int:
            alloc_base = claripy.BVV(alloc_base, state.arch.bits)

        for i, val in enumerate(vals):
            vals[i] = allocator.translate(val, alloc_base)

        #
        # STEP 3: store everything!
        #

        allocator.apply(state, alloc_base)

        for loc, val in zip(arg_locs, vals):
            if val.length > loc.size * 8:
                raise ValueError("Can't fit value {} into location {}".format(repr(val), repr(loc)))
            loc.set_value(state, val, endness='Iend_BE', stack_base=stack_base)
        self.return_addr.set_value(state, ret_addr, stack_base=stack_base)

    def teardown_callsite(self, state, return_val=None, arg_types=None, force_callee_cleanup=False):
        """
        This function performs the actions of the callee as it's getting ready to return.
        It returns the address to return to.

        :param state:                   The state to mutate
        :param return_val:              The value to return
        :param arg_types:               The fp-ness of each of the args. Used to calculate sizes to clean up
        :param force_callee_cleanup:    If we should clean up the stack allocation for the arguments even if it's not
                                        the callee's job to do so

        TODO: support the stack_base parameter from setup_callsite...? Does that make sense in this context?
        Maybe it could make sense by saying that you pass it in as something like the "saved base pointer" value?
        """
        if return_val is not None:
            self.set_return_val(state, return_val)

        ret_addr = self.return_addr.get_value(state)

        if state.arch.sp_offset is not None:
            if force_callee_cleanup or self.CALLEE_CLEANUP:
                if arg_types is not None:
                    session = self.arg_session
                    state.regs.sp += self.stack_space([session.next_arg(x) for x in arg_types])
                elif self.args is not None:
                    state.regs.sp += self.stack_space(self.args)
                else:
                    l.warning("Can't perform callee cleanup when I have no idea how many arguments there are! Assuming 0")
                    state.regs.sp += self.STACKARG_SP_DIFF
            else:
                state.regs.sp += self.STACKARG_SP_DIFF

        return ret_addr


    # pylint: disable=unused-argument
    def get_return_val(self, state, is_fp=None, size=None, stack_base=None):
        """
        Get the return value out of the given state
        """
        ty = self.func_ty.returnty if self.func_ty is not None else None
        if self.ret_val is not None:
            loc = self.ret_val
        elif is_fp is not None:
            loc = self.FP_RETURN_VAL if is_fp else self.RETURN_VAL
        elif ty is not None:
            loc = self.FP_RETURN_VAL if isinstance(ty, SimTypeFloat) else self.RETURN_VAL
        else:
            loc = self.RETURN_VAL

        if loc is None:
            raise NotImplementedError("This SimCC doesn't know how to get this value - should be implemented")

        val = loc.get_value(state, stack_base=stack_base, size=None if ty is None else ty.size//state.arch.byte_width)
        if self.is_fp_arg(loc) or self.is_fp_value(val) or isinstance(ty, SimTypeFloat):
            val = val.raw_to_fp()
        return val

    def set_return_val(self, state, val, is_fp=None, size=None, stack_base=None):
        """
        Set the return value into the given state
        """
        ty = self.func_ty.returnty if self.func_ty is not None else None
        try:
            betterval = self._standardize_value(val, ty, state, None)
        except AttributeError:
            raise ValueError("Can't fit value %s into a return value" % repr(val))

        if self.ret_val is not None:
            loc = self.ret_val
        elif is_fp is not None:
            loc = self.fp_return_val if is_fp else self.return_val
        elif ty is not None:
            loc = self.fp_return_val if isinstance(ty, SimTypeFloat) else self.return_val
        else:
            loc = self.fp_return_val if self.is_fp_value(val) else self.return_val

        if loc is None:
            raise NotImplementedError("This SimCC doesn't know how to store this value - should be implemented")
        loc.set_value(state, betterval, endness='Iend_BE', stack_base=stack_base)


    #
    # Helper functions
    #

    @staticmethod
    def _standardize_value(arg, ty, state, alloc):
        check = ty is not None
        if check:
            ty = ty.with_arch(state.arch)

        if isinstance(arg, SimActionObject):
            return SimCC._standardize_value(arg.ast, ty, state, alloc)
        elif isinstance(arg, PointerWrapper):
            if check and not isinstance(ty, SimTypePointer):
                raise TypeError("Type mismatch: expected %s, got pointer-wrapper" % ty.name)

            real_value = SimCC._standardize_value(arg.value, ty.pts_to if check else None, state, alloc)
            return alloc(real_value, state)

        elif isinstance(arg, (str, bytes)):
            if type(arg) is str:
                arg = arg.encode()
            arg += b'\0'
            ref = False
            if check:
                if isinstance(ty, SimTypePointer) and \
                        isinstance(ty.pts_to, SimTypeChar):
                    ref = True
                elif isinstance(ty, SimTypeFixedSizeArray) and \
                        isinstance(ty.elem_type, SimTypeChar):
                    ref = False
                    if len(arg) > ty.length:
                        raise TypeError("String %s is too long for %s" % (repr(arg), ty.name))
                    arg = arg.ljust(ty.length, b'\0')
                elif isinstance(ty, SimTypeArray) and \
                        isinstance(ty.elem_type, SimTypeChar):
                    ref = True
                    if ty.length is not None:
                        if len(arg) > ty.length:
                            raise TypeError("String %s is too long for %s" % (repr(arg), ty.name))
                        arg = arg.ljust(ty.length, b'\0')
                elif isinstance(ty, SimTypeString):
                    ref = False
                    if len(arg) > ty.length + 1:
                        raise TypeError("String %s is too long for %s" % (repr(arg), ty.name))
                    arg = arg.ljust(ty.length + 1, b'\0')
                else:
                    raise TypeError("Type mismatch: Expected %s, got char*" % ty.name)
            val = SimCC._standardize_value(list(arg), SimTypeFixedSizeArray(SimTypeChar(), len(arg)), state, alloc)
            if ref:
                val = alloc(val, state)
            return val

        elif isinstance(arg, list):
            ref = False
            subty = None
            if check:
                if isinstance(ty, SimTypePointer):
                    ref = True
                    subty = ty.pts_to
                elif isinstance(ty, SimTypeFixedSizeArray):
                    ref = False
                    subty = ty.elem_type
                    if len(arg) != ty.length:
                        raise TypeError("Array %s is the wrong length for %s" % (repr(arg), ty.name))
                elif isinstance(ty, SimTypeArray):
                    ref = True
                    subty = ty.elem_type
                    if ty.length is not None:
                        if len(arg) != ty.length:
                            raise TypeError("Array %s is the wrong length for %s" % (repr(arg), ty.name))
                else:
                    raise TypeError("Type mismatch: Expected %s, got char*" % ty.name)
            else:
                types = list(map(type, arg))
                if types[1:] != types[:-1]:
                    raise TypeError("All elements of list must be of same type")

            val = claripy.Concat(*[SimCC._standardize_value(sarg, subty, state, alloc) for sarg in arg])
            if ref:
                val = alloc(val, state)
            return val

        elif isinstance(arg, tuple):
            if check:
                if not isinstance(ty, SimStruct):
                    raise TypeError("Type mismatch: Expected %s, got tuple (i.e. struct)" % ty.name)
                if len(arg) != len(ty.fields):
                    raise TypeError("Wrong number of fields in struct, expected %d got %d" % (len(ty.fields), len(arg)))
                return claripy.Concat(*[SimCC._standardize_value(sarg, sty, state, alloc)
                                        for sarg, sty
                                        in zip(arg, ty.fields.values())])
            else:
                return claripy.Concat(*[SimCC._standardize_value(sarg, None, state, alloc) for sarg in arg])

        elif isinstance(arg, int):
            if check and isinstance(ty, SimTypeFloat):
                return SimCC._standardize_value(float(arg), ty, state, alloc)

            val = state.solver.BVV(arg, ty.size if check else state.arch.bits)
            if state.arch.memory_endness == 'Iend_LE':
                val = val.reversed
            return val

        elif isinstance(arg, float):
            sort = claripy.FSORT_FLOAT
            if check:
                if isinstance(ty, SimTypeDouble):
                    sort = claripy.FSORT_DOUBLE
                elif isinstance(ty, SimTypeFloat):
                    pass
                else:
                    raise TypeError("Type mismatch: expectd %s, got float" % ty.name)
            else:
                sort = claripy.FSORT_DOUBLE if state.arch.bits == 64 else claripy.FSORT_FLOAT

            val = claripy.fpToIEEEBV(claripy.FPV(arg, sort))
            if state.arch.memory_endness == 'Iend_LE':
                val = val.reversed      # pylint: disable=no-member
            return val

        elif isinstance(arg, claripy.ast.FP):
            val = claripy.fpToIEEEBV(arg)
            if state.arch.memory_endness == 'Iend_LE':
                val = val.reversed      # pylint: disable=no-member
            return val

        elif isinstance(arg, claripy.ast.Base):
            endswap = False
            bypass_sizecheck = False
            if check:
                if isinstance(ty, SimTypePointer):
                    # we have been passed an AST as a pointer argument. is this supposed to be the pointer or the
                    # content of the pointer?
                    # in the future (a breaking change) we should perhaps say it ALWAYS has to be the pointer itself
                    # but for now use the heuristic that if it's the right size for the pointer it is the pointer
                    endswap = True
                elif isinstance(ty, SimTypeReg):
                    # definitely endswap.
                    # TODO: should we maybe pad the value to the type size here?
                    endswap = True
                    bypass_sizecheck = True
            else:
                # if we know nothing about the type assume it's supposed to be an int if it looks like an int
                endswap = True

            # yikes
            if endswap and state.arch.memory_endness == 'Iend_LE' and (bypass_sizecheck or arg.length == state.arch.bits):
                arg = arg.reversed
            return arg

        else:
            raise TypeError("I don't know how to serialize %s." % repr(arg))

    def __repr__(self):
        return "<{}: {}->{}, sp_delta={}>".format(self.__class__.__name__,
                                                  self.args,
                                                  self.ret_val,
                                                  self.sp_delta)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        def _compare_args(args0, args1):
            if args0 is None and args1 is None:
                return True
            if args0 is None or args1 is None:
                return False
            return set(args0) == set(args1)

        return _compare_args(self.args, other.args) and \
               self.ret_val == other.ret_val and \
               self.sp_delta == other.sp_delta

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
        some_both_args = [next(both_iter) for _ in range(len(args))]

        for arg in args:
            if arg not in all_fp_args and arg not in all_int_args and arg not in some_both_args:
                return False

        return True

    @staticmethod
    def find_cc(arch, args, sp_delta):
        """
        Pinpoint the best-fit calling convention and return the corresponding SimCC instance, or None if no fit is
        found.

        :param Arch arch:       An ArchX instance. Can be obtained from archinfo.
        :param list args:       A list of arguments.
        :param int sp_delta:    The change of stack pointer before and after the call is made.
        :return:                A calling convention instance, or None if none of the SimCC subclasses seems to fit the
                                arguments provided.
        :rtype:                 SimCC or None
        """
        if arch.name not in CC:
            return None
        possible_cc_classes = CC[arch.name]
        for cc_cls in possible_cc_classes:
            if cc_cls._match(arch, args, sp_delta):
                return cc_cls(arch, args=args, sp_delta=sp_delta)
        return None


    def get_arg_info(self, state, is_fp=None, sizes=None):
        """
        This is just a simple wrapper that collects the information from various locations
        is_fp and sizes are passed to self.arg_locs and self.get_args
        :param angr.SimState state: The state to evaluate and extract the values from
        :return:    A list of tuples, where the nth tuple is (type, name, location, value) of the nth argument
        """

        argument_locations = self.arg_locs(is_fp=is_fp, sizes=sizes)
        argument_values = self.get_args(state, is_fp=is_fp, sizes=sizes)

        if self.func_ty:
            argument_types = self.func_ty.args
            argument_names = self.func_ty.arg_names if self.func_ty.arg_names else ['unknown'] * len(self.func_ty.args)
        else:
            argument_types = [SimTypeTop] * len(argument_locations)
            argument_names = ['unknown'] * len(argument_locations)
        return list(zip(argument_types, argument_names, argument_locations, argument_values))

class SimLyingRegArg(SimRegArg):
    """
    A register that LIES about the types it holds
    """
    def __init__(self, name):
        # TODO: This looks byte-related.  Make sure to use Arch.byte_width
        super(SimLyingRegArg, self).__init__(name, 8)

    def get_value(self, state, size=None, endness=None, **kwargs):  # pylint:disable=arguments-differ
        #val = super(SimLyingRegArg, self).get_value(state, **kwargs)
        val = getattr(state.regs, self.reg_name)
        if endness and endness != state.arch.register_endness:
            val = val.reversed
        if size == 4:
            val = claripy.fpToFP(claripy.fp.RM.RM_NearestTiesEven, val.raw_to_fp(), claripy.FSORT_FLOAT)
        return val

    def set_value(self, state, val, size=None, endness=None, **kwargs):  # pylint:disable=arguments-differ
        if size == 4:
            if state.arch.register_endness == 'IEnd_LE' and endness == 'IEnd_BE':
                # pylint: disable=no-member
                val = claripy.fpToFP(claripy.fp.RM.RM_NearestTiesEven, val.reversed.raw_to_fp(), claripy.FSORT_DOUBLE).reversed
            else:
                val = claripy.fpToFP(claripy.fp.RM.RM_NearestTiesEven, val.raw_to_fp(), claripy.FSORT_DOUBLE)
        if endness and endness != state.arch.register_endness:
            val = val.reversed
        setattr(state.regs, self.reg_name, val)
        #super(SimLyingRegArg, self).set_value(state, val, endness=endness, **kwargs)

class SimCCCdecl(SimCC):
    ARG_REGS = [] # All arguments are passed in stack
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 4 # Return address is pushed on to stack by call
    CALLER_SAVED_REGS = ['eax', 'ecx', 'edx']
    RETURN_VAL = SimRegArg('eax', 4)
    OVERFLOW_RETURN_VAL = SimRegArg('edx', 4)
    FP_RETURN_VAL = SimLyingRegArg('st0')
    RETURN_ADDR = SimStackArg(0, 4)
    ARCH = archinfo.ArchX86

class SimCCStdcall(SimCCCdecl):
    CALLEE_CLEANUP = True

class SimCCMicrosoftAMD64(SimCC):
    ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
    FP_ARG_REGS = ['xmm0', 'xmm1', 'xmm2', 'xmm3']
    STACKARG_SP_DIFF = 8 # Return address is pushed on to stack by call
    STACKARG_SP_BUFF = 32 # 32 bytes of shadow stack space
    RETURN_VAL = SimRegArg('rax', 8)
    OVERFLOW_RETURN_VAL = SimRegArg('rdx', 8)
    FP_RETURN_VAL = SimRegArg('xmm0', 32)
    RETURN_ADDR = SimStackArg(0, 8)
    ARCH = archinfo.ArchAMD64

class SimCCX86LinuxSyscall(SimCC):
    ARG_REGS = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg('eax', 4)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 4)
    ARCH = archinfo.ArchX86

    @classmethod
    def _match(cls, arch, args, sp_delta): # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.eax

class SimCCX86WindowsSyscall(SimCC):
    # TODO: Make sure the information is correct
    ARG_REGS = [ ]
    FP_ARG_REGS = [ ]
    RETURN_VAL = SimRegArg('eax', 4)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 4)
    ARCH = archinfo.ArchX86

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.eax

class SimCCSystemVAMD64(SimCC):
    ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
    FP_ARG_REGS = ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']
    STACKARG_SP_DIFF = 8 # Return address is pushed on to stack by call
    CALLER_SAVED_REGS = [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10', 'r11', 'rax', ]
    RETURN_ADDR = SimStackArg(0, 8)
    RETURN_VAL = SimRegArg('rax', 8)
    OVERFLOW_RETURN_VAL = SimRegArg('rdx', 8)
    FP_RETURN_VAL = SimRegArg('xmm0', 32)
    ARCH = archinfo.ArchAMD64
    STACK_ALIGNMENT = 16

    def __init__(self, arch, args=None, ret_val=None, sp_delta=None, func_ty=None):
        super(SimCCSystemVAMD64, self).__init__(arch, args, ret_val, sp_delta, func_ty)

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
        some_both_args = [next(both_iter) for _ in range(len(args))]

        for arg in args:
            if arg not in all_fp_args and arg not in all_int_args and arg not in some_both_args:
                if isinstance(arg, SimStackArg) and arg.stack_offset == 0:
                    continue        # ignore return address?
                return False

        return True

class SimCCAMD64LinuxSyscall(SimCC):
    ARG_REGS = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
    RETURN_VAL = SimRegArg('rax', 8)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    ARCH = archinfo.ArchAMD64

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.rax

class SimCCAMD64WindowsSyscall(SimCC):
    # TODO: Make sure the information is correct
    ARG_REGS = [ ]
    FP_ARG_REGS = [ ]
    RETURN_VAL = SimRegArg('rax', 8)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    ARCH = archinfo.ArchAMD64

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.rax

class SimCCARM(SimCC):
    ARG_REGS = [ 'r0', 'r1', 'r2', 'r3' ]
    FP_ARG_REGS = []    # TODO: ???
    CALLER_SAVED_REGS = [ 'r0', 'r1', 'r2', 'r3' ]
    RETURN_ADDR = SimRegArg('lr', 4)
    RETURN_VAL = SimRegArg('r0', 4)
    ARCH = archinfo.ArchARM

class SimCCARMLinuxSyscall(SimCC):
    # TODO: Make sure all the information is correct
    ARG_REGS = [ 'r0', 'r1', 'r2', 'r3' ]
    FP_ARG_REGS = []    # TODO: ???
    RETURN_ADDR = SimRegArg('ip_at_syscall', 4)
    RETURN_VAL = SimRegArg('r0', 4)
    ARCH = archinfo.ArchARM

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.r7

class SimCCAArch64(SimCC):
    ARG_REGS = [ 'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7' ]
    FP_ARG_REGS = []    # TODO: ???
    RETURN_ADDR = SimRegArg('lr', 8)
    RETURN_VAL = SimRegArg('x0', 8)
    ARCH = archinfo.ArchAArch64

class SimCCAArch64LinuxSyscall(SimCC):
    # TODO: Make sure all the information is correct
    ARG_REGS = [ 'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7' ]
    FP_ARG_REGS = []    # TODO: ???
    RETURN_VAL = SimRegArg('x0', 8)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    ARCH = archinfo.ArchAArch64

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.x8

class SimCCO32(SimCC):
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 16
    CALLER_SAVED_REGS = []   # TODO: ???
    RETURN_ADDR = SimRegArg('lr', 4)
    RETURN_VAL = SimRegArg('v0', 4)
    ARCH = archinfo.ArchMIPS32

class SimCCO32LinuxSyscall(SimCC):
    # TODO: Make sure all the information is correct
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    FP_ARG_REGS = []    # TODO: ???
    RETURN_VAL = SimRegArg('v0', 4)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 4)
    ARCH = archinfo.ArchMIPS32

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.v0

class SimCCO64(SimCC):      # TODO: add n32 and n64
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 32
    RETURN_ADDR = SimRegArg('lr', 8)
    RETURN_VAL = SimRegArg('v0', 8)
    ARCH = archinfo.ArchMIPS64

class SimCCO64LinuxSyscall(SimCC):
    # TODO: Make sure all the information is correct
    ARG_REGS = [ 'a0', 'a1', 'a2', 'a3' ]
    FP_ARG_REGS = []    # TODO: ???
    RETURN_VAL = SimRegArg('v0', 8)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    ARCH = archinfo.ArchMIPS64

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.v0

class SimCCPowerPC(SimCC):
    ARG_REGS = [ 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 8
    RETURN_ADDR = SimRegArg('lr', 4)
    RETURN_VAL = SimRegArg('r3', 4)
    ARCH = archinfo.ArchPPC32

class SimCCPowerPCLinuxSyscall(SimCC):
    # TODO: Make sure all the information is correct
    ARG_REGS = ['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10']
    FP_ARG_REGS = [ ]
    RETURN_VAL = SimRegArg('r3', 4)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 4)
    ARCH = archinfo.ArchPPC32

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.r0

class SimCCPowerPC64(SimCC):
    ARG_REGS = [ 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10' ]
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_BUFF = 0x70
    RETURN_ADDR = SimRegArg('lr', 8)
    RETURN_VAL = SimRegArg('r3', 8)
    ARCH = archinfo.ArchPPC64

class SimCCPowerPC64LinuxSyscall(SimCC):
    # TODO: Make sure all the information is correct
    ARG_REGS = [ ]
    FP_ARG_REGS = [ ]
    RETURN_VAL = SimRegArg('r3', 8)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    ARCH = archinfo.ArchPPC64

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.r0

class SimCCSoot(SimCC):
    ARCH = archinfo.ArchSoot
    ARG_REGS = []

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

class SimCCS390X(SimCC):
    ARG_REGS = ['r2', 'r3', 'r4', 'r5', 'r6']
    FP_ARG_REGS = ['f0', 'f2', 'f4', 'f6']
    STACKARG_SP_BUFF = 0xa0
    RETURN_ADDR = SimRegArg('r14', 8)
    RETURN_VAL = SimRegArg('r2', 8)
    ARCH = archinfo.ArchS390X

class SimCCS390XLinuxSyscall(SimCC):
    ARG_REGS = ['r2', 'r3', 'r4', 'r5', 'r6', 'r7']
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg('r2', 8)
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)
    ARCH = archinfo.ArchS390X

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.r1

CC = {
    'AMD64': [
        SimCCSystemVAMD64,
    ],
    'X86': [
        SimCCCdecl,
    ],
    'ARMEL': [
        SimCCARM,
    ],
    'ARMHF': [
        SimCCARM,
    ],
    'ARMCortexM': [
        SimCCARM,
    ],
    'MIPS32': [
        SimCCO32,
    ],
    'MIPS64': [
        SimCCO64,
    ],
    'PPC32': [
        SimCCPowerPC,
    ],
    'PPC64': [
        SimCCPowerPC64,
    ],
    'AARCH64': [
        SimCCAArch64,
    ],
    'S390X': [
        SimCCS390X,
    ],
}


DEFAULT_CC: Dict[str,type] = {
    'AMD64': SimCCSystemVAMD64,
    'X86': SimCCCdecl,
    'ARMEL': SimCCARM,
    'ARMHF': SimCCARM,
    'ARMCortexM': SimCCARM,
    'MIPS32': SimCCO32,
    'MIPS64': SimCCO64,
    'PPC32': SimCCPowerPC,
    'PPC64': SimCCPowerPC64,
    'AARCH64': SimCCAArch64,
    'Soot': SimCCSoot,
    'AVR': SimCCUnknown,
    'MSP': SimCCUnknown,
    'S390X': SimCCS390X,
}


def register_default_cc(arch, cc):
    DEFAULT_CC[arch] = cc

SYSCALL_CC = {
    'X86': {
        'default': SimCCX86LinuxSyscall,
        'Linux': SimCCX86LinuxSyscall,
        'Windows': SimCCX86WindowsSyscall,
        'CGC': SimCCX86LinuxSyscall,
    },
    'AMD64': {
        'default': SimCCAMD64LinuxSyscall,
        'Linux': SimCCAMD64LinuxSyscall,
        'Windows': SimCCAMD64WindowsSyscall,
    },
    'ARMEL': {
        'default': SimCCARMLinuxSyscall,
        'Linux': SimCCARMLinuxSyscall,
    },
    'ARMCortexM': {
        # FIXME: TODO: This is wrong.  Fill in with a real CC when we support CM syscalls
        'default': SimCCARMLinuxSyscall,
    },
    'ARMHF': {
        'default': SimCCARMLinuxSyscall,
        'Linux': SimCCARMLinuxSyscall,
    },
    'AARCH64': {
        'default': SimCCAArch64LinuxSyscall,
        'Linux': SimCCAArch64LinuxSyscall,
    },
    'MIPS32': {
        'default': SimCCO32LinuxSyscall,
        'Linux': SimCCO32LinuxSyscall,
    },
    'MIPS64': {
        'default': SimCCO64LinuxSyscall,
        'Linux': SimCCO64LinuxSyscall,
    },
    'PPC32': {
        'default': SimCCPowerPCLinuxSyscall,
        'Linux': SimCCPowerPCLinuxSyscall,
    },
    'PPC64': {
        'default': SimCCPowerPC64LinuxSyscall,
        'Linux': SimCCPowerPC64LinuxSyscall,
    },
    'S390X': {
        'default': SimCCS390XLinuxSyscall,
        'Linux': SimCCS390XLinuxSyscall,
    },
}


def register_syscall_cc(arch, os, cc):
    if arch not in SYSCALL_CC:
        SYSCALL_CC[arch] = {}
    SYSCALL_CC[arch][os] = cc

SyscallCC = SYSCALL_CC
DefaultCC = DEFAULT_CC
