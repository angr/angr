# pylint:disable=line-too-long,missing-class-docstring,no-self-use
import logging
from typing import Optional, List, Dict, Type, Union
from collections import defaultdict

import claripy
import archinfo
from archinfo import RegisterName
from unique_log_filter import UniqueLogFilter

from .errors import AngrTypeError
from .sim_type import (
    SimType,
    SimTypeChar,
    SimTypePointer,
    SimTypeFixedSizeArray,
    SimTypeArray,
    SimTypeString,
    SimTypeFunction,
    SimTypeFloat,
    SimTypeDouble,
    SimTypeReg,
    SimStruct,
    SimStructValue,
    SimTypeInt,
    SimTypeNum,
    SimUnion,
    SimTypeBottom,
    parse_signature,
    SimTypeReference,
)
from .state_plugins.sim_action_object import SimActionObject
from .engines.soot.engine import SootMixin

l = logging.getLogger(name=__name__)
l.addFilter(UniqueLogFilter())


class PointerWrapper:
    def __init__(self, value, buffer=False):
        self.value = value
        self.buffer = buffer


class AllocHelper:
    def __init__(self, ptrsize):
        self.base = claripy.BVS("alloc_base", ptrsize)
        self.ptr = self.base
        self.stores = {}

    def alloc(self, size):
        out = self.ptr
        self.ptr += size
        return out

    def dump(self, val, state, loc=None):
        if loc is None:
            loc = self.stack_loc(val, state.arch)
        self.stores[self.ptr.cache_key] = (val, loc)
        return self.alloc(self.calc_size(val, state.arch))

    def translate(self, val, base):
        if type(val) is SimStructValue:
            return SimStructValue(
                val.struct, {field: self.translate(subval, base) for field, subval in val._values.items()}
            )
        if isinstance(val, claripy.Bits):
            return val.replace(self.base, base)
        if type(val) is list:
            return [self.translate(subval, base) for subval in val]
        raise TypeError(type(val))

    def apply(self, state, base):
        for ptr, (val, loc) in self.stores.items():
            translated_val = self.translate(val, base)
            translated_ptr = self.translate(ptr.ast, base)
            loc.set_value(state, translated_val, stack_base=translated_ptr)

    def size(self):
        val = self.translate(self.ptr, claripy.BVV(0, len(self.ptr)))
        assert val.op == "BVV"
        return abs(val.args[0])

    @classmethod
    def calc_size(cls, val, arch):
        if type(val) is SimStructValue:
            return val.struct.size // arch.byte_width
        if isinstance(val, claripy.Bits):
            return len(val) // arch.byte_width
        if type(val) is list:
            # TODO real strides
            if len(val) == 0:
                return 0
            return cls.calc_size(val[0], arch) * len(val)
        raise TypeError(type(val))

    @classmethod
    def stack_loc(cls, val, arch, offset=0):
        if isinstance(val, claripy.Bits):
            return SimStackArg(offset, len(val) // arch.byte_width)
        if type(val) is list:
            # TODO real strides
            if len(val) == 0:
                return SimArrayArg([])
            stride = cls.calc_size(val[0], arch)
            return SimArrayArg([cls.stack_loc(subval, arch, offset + i * stride) for i, subval in enumerate(val)])
        if type(val) is SimStructValue:
            return SimStructArg(
                val.struct,
                {
                    field: cls.stack_loc(subval, arch, offset + val.struct.offsets[field])
                    for field, subval in val._values.items()
                },
            )
        raise TypeError(type(val))


def refine_locs_with_struct_type(
    arch: archinfo.Arch, locs: List, arg_type: SimType, offset: int = 0, treat_bot_as_int=True
):
    # CONTRACT FOR USING THIS METHOD: locs must be a list of locs which are all wordsize
    # ADDITIONAL NUANCE: this will not respect the need for big-endian integers to be stored at the end of words.
    # that's why this is named with_struct_type, because it will blindly trust the offsets given to it.

    if treat_bot_as_int and isinstance(arg_type, SimTypeBottom):
        arg_type = SimTypeInt(label=arg_type.label).with_arch(arch)

    if isinstance(arg_type, (SimTypeReg, SimTypeNum, SimTypeFloat)):
        seen_bytes = 0
        pieces = []
        while seen_bytes < arg_type.size // arch.byte_width:
            start_offset = offset + seen_bytes
            chunk = start_offset // arch.bytes
            chunk_offset = start_offset % arch.bytes
            chunk_remaining = arch.bytes - chunk_offset
            type_remaining = arg_type.size // arch.byte_width - seen_bytes
            use_bytes = min(chunk_remaining, type_remaining)
            pieces.append(locs[chunk].refine(size=use_bytes, offset=chunk_offset))
            seen_bytes += use_bytes

        if len(pieces) == 1:
            piece = pieces[0]
        else:
            piece = SimComboArg(pieces)
        if isinstance(arg_type, SimTypeFloat):
            piece.is_fp = True
        return piece
    if isinstance(arg_type, SimTypeFixedSizeArray):
        # TODO explicit stride
        locs = [
            refine_locs_with_struct_type(
                arch, locs, arg_type.elem_type, offset=offset + i * arg_type.elem_type.size // arch.byte_width
            )
            for i in range(arg_type.length)
        ]
        return SimArrayArg(locs)
    if isinstance(arg_type, SimStruct):
        locs = {
            field: refine_locs_with_struct_type(arch, locs, field_ty, offset=offset + arg_type.offsets[field])
            for field, field_ty in arg_type.fields.items()
        }
        return SimStructArg(arg_type, locs)
    if isinstance(arg_type, SimUnion):
        # Treat a SimUnion as functionality equivalent to its longest member
        for member in arg_type.members.values():
            if member.size == arg_type.size:
                return refine_locs_with_struct_type(arch, locs, member, offset)

    raise TypeError("I don't know how to lay out a %s" % arg_type)


class SerializableIterator:
    def __iter__(self):
        return self

    def __next__(self):
        raise NotImplementedError

    def getstate(self):
        raise NotImplementedError

    def setstate(self, state):
        raise NotImplementedError


class SerializableListIterator(SerializableIterator):
    def __init__(self, lst):
        self._lst = lst
        self._index = 0

    def __next__(self):
        if self._index >= len(self._lst):
            raise StopIteration
        result = self._lst[self._index]
        self._index += 1
        return result

    def getstate(self):
        return self._index

    def setstate(self, state):
        self._index = state


class SerializableCounter(SerializableIterator):
    def __init__(self, start, stride, mapping=lambda x: x):
        self._next = start
        self._stride = stride
        self._mapping = mapping

    def __next__(self):
        result = self._mapping(self._next)
        self._next += self._stride
        return result

    def getstate(self):
        return self._next

    def setstate(self, state):
        self._next = state


class SimFunctionArgument:
    """
    Represent a generic function argument.

    :ivar int size:    The size of the argument, in number of bytes.
    :ivar bool is_fp:  Whether loads from this location should return a floating point bitvector
    """

    def __init__(self, size, is_fp=False):
        self.size = size
        self.is_fp = is_fp

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(("function_argument", self.size))

    def check_value_set(self, value, arch):
        if not isinstance(value, claripy.ast.Base) and self.size is None:
            raise TypeError("Only claripy objects may be stored through SimFunctionArgument when size is not provided")
        if self.size is not None and isinstance(value, claripy.ast.Base) and self.size * arch.byte_width < value.length:
            raise TypeError("%s doesn't fit in an argument of size %d" % (value, self.size))
        if isinstance(value, int):
            value = claripy.BVV(value, self.size * arch.byte_width)
        if isinstance(value, float):
            if self.size not in (4, 8):
                raise ValueError("What do I do with a float %d bytes long" % self.size)
            value = claripy.FPV(value, claripy.FSORT_FLOAT if self.size == 4 else claripy.FSORT_DOUBLE)
        return value.raw_to_bv()

    def check_value_get(self, value):
        if self.is_fp:
            return value.raw_to_fp()
        return value

    def set_value(self, state, value, **kwargs):
        raise NotImplementedError

    def get_value(self, state, **kwargs):
        raise NotImplementedError

    def refine(self, size, arch=None, offset=None, is_fp=None):
        raise NotImplementedError

    def get_footprint(self) -> List[Union["SimRegArg", "SimStackArg"]]:
        """
        Return a list of SimRegArg and SimStackArgs that are the base components used for this location
        """
        raise NotImplementedError


class SimRegArg(SimFunctionArgument):
    """
    Represents a function argument that has been passed in a register.

    :ivar string reg_name:    The name of the represented register.
    :ivar int size:           The size of the data to store, in number of bytes.
    :ivar reg_offset:         The offset into the register to start storing data.
    :ivar clear_entire_reg:   Whether a store to this register should zero the unused parts of the register.
    :ivar bool is_fp:  Whether loads from this location should return a floating point bitvector
    """

    def __init__(self, reg_name: RegisterName, size: int, reg_offset=0, is_fp=False, clear_entire_reg=False):
        super().__init__(size, is_fp)
        self.reg_name = reg_name
        self.reg_offset = reg_offset
        self.clear_entire_reg = clear_entire_reg

    def get_footprint(self):
        yield self

    def __repr__(self):
        return "<%s>" % self.reg_name

    def __eq__(self, other):
        return type(other) is SimRegArg and self.reg_name == other.reg_name and self.reg_offset == other.reg_offset

    def __hash__(self):
        return hash((self.size, self.reg_name, self.reg_offset))

    def check_offset(self, arch):
        return arch.registers[self.reg_name][0] + self.reg_offset

    def set_value(self, state, value, **kwargs):  # pylint: disable=unused-argument,arguments-differ
        value = self.check_value_set(value, state.arch)
        offset = self.check_offset(state.arch)
        if self.clear_entire_reg:
            state.registers.store(self.reg_name, 0)
        state.registers.store(offset, value, size=self.size)

    def get_value(self, state, **kwargs):  # pylint: disable=unused-argument,arguments-differ
        offset = self.check_offset(state.arch)
        return self.check_value_get(state.registers.load(offset, size=self.size))

    def refine(self, size, arch=None, offset=None, is_fp=None):
        passed_offset_none = offset is None
        if offset is None:
            if arch is None:
                raise ValueError("Need to specify either offset or arch in order to refine a register argument")
            if arch.register_endness == "Iend_LE":
                offset = 0
            else:
                offset = self.size - size
        if is_fp is None:
            is_fp = self.is_fp
        return SimRegArg(self.reg_name, size, self.reg_offset + offset, is_fp, clear_entire_reg=passed_offset_none)

    def sse_extend(self):
        return SimRegArg(self.reg_name, self.size, self.reg_offset + self.size, is_fp=self.is_fp)


class SimStackArg(SimFunctionArgument):
    """
    Represents a function argument that has been passed on the stack.

    :var int stack_offset:    The position of the argument relative to the stack pointer after the function prelude.
    :ivar int size:           The size of the argument, in number of bytes.
    :ivar bool is_fp:  Whether loads from this location should return a floating point bitvector
    """

    def __init__(self, stack_offset, size, is_fp=False):
        SimFunctionArgument.__init__(self, size, is_fp)
        self.stack_offset = stack_offset

    def get_footprint(self):
        yield self

    def __repr__(self):
        return "[%#x]" % self.stack_offset

    def __eq__(self, other):
        return type(other) is SimStackArg and self.stack_offset == other.stack_offset

    def __hash__(self):
        return hash((self.size, self.stack_offset))

    def set_value(self, state, value, stack_base=None, **kwargs):  # pylint: disable=arguments-differ
        value = self.check_value_set(value, state.arch)
        if stack_base is None:
            stack_base = state.regs.sp
        state.memory.store(stack_base + self.stack_offset, value, endness=state.arch.memory_endness)

    def get_value(self, state, stack_base=None, **kwargs):  # pylint: disable=arguments-differ
        if stack_base is None:
            stack_base = state.regs.sp
        value = state.memory.load(stack_base + self.stack_offset, endness=state.arch.memory_endness, size=self.size)
        return self.check_value_get(value)

    def refine(self, size, arch=None, offset=None, is_fp=None):
        if offset is None:
            if arch is None:
                raise ValueError("Need to specify either offset or arch in order to refine a stack argument")
            if arch.register_endness == "Iend_LE":
                offset = 0
            else:
                offset = self.size - size
        if is_fp is None:
            is_fp = self.is_fp
        return SimStackArg(self.stack_offset + offset, size, is_fp)


class SimComboArg(SimFunctionArgument):
    """
    An argument which spans multiple storage locations. Locations should be given least-significant first.
    """

    def __init__(self, locations, is_fp=False):
        super().__init__(sum(x.size for x in locations), is_fp=is_fp)
        self.locations = locations

    def get_footprint(self):
        for x in self.locations:
            yield from x.get_footprint()

    def __repr__(self):
        return "SimComboArg(%s)" % repr(self.locations)

    def __eq__(self, other):
        return type(other) is SimComboArg and all(a == b for a, b in zip(self.locations, other.locations))

    def set_value(self, state, value, **kwargs):  # pylint:disable=arguments-differ
        value = self.check_value_set(value, state.arch)
        cur = 0
        for loc in self.locations:
            size_bits = loc.size * state.arch.byte_width
            loc.set_value(state, value[cur + size_bits - 1 : cur], **kwargs)
            cur += size_bits

    def get_value(self, state, **kwargs):  # pylint:disable=arguments-differ
        vals = []
        for loc in reversed(self.locations):
            vals.append(loc.get_value(state, **kwargs))
        return self.check_value_get(state.solver.Concat(*vals))


class SimStructArg(SimFunctionArgument):
    """
    An argument which de/serializes a struct from a list of storage locations

    :ivar struct:   The simtype describing the structure
    :ivar locs:     The storage locations to use
    """

    def __init__(self, struct: SimStruct, locs: Dict[str, SimFunctionArgument]):
        super().__init__(sum(loc.size for loc in locs.values()))
        self.struct = struct
        self.locs = locs

    def get_footprint(self):
        for x in self.locs.values():
            yield from x.get_footprint()

    def get_value(self, state, **kwargs):
        return SimStructValue(
            self.struct, {field: getter.get_value(state, **kwargs) for field, getter in self.locs.items()}
        )

    def set_value(self, state, value, **kwargs):
        for field, setter in self.locs.items():
            setter.set_value(state, value[field], **kwargs)


class SimArrayArg(SimFunctionArgument):
    def __init__(self, locs):
        super().__init__(sum(loc.size for loc in locs))
        self.locs = locs

    def get_footprint(self):
        for x in self.locs:
            yield from x.get_footprint()

    def get_value(self, state, **kwargs):
        return [getter.get_value(state, **kwargs) for getter in self.locs]

    def set_value(self, state, value, **kwargs):
        if len(value) != len(self.locs):
            raise TypeError("Expected %d elements, got %d" % (len(self.locs), len(value)))
        for subvalue, setter in zip(value, self.locs):
            setter.set_value(state, subvalue, **kwargs)


class SimReferenceArgument(SimFunctionArgument):
    """
    A function argument which is passed by reference.

    :ivar ptr_loc:      The location the reference's pointer is stored
    :ivar main_loc:     A SimStackArgument describing how to load the argument's value as if it were stored at offset
                        zero on the stack. It will be passed ``stack_base=ptr_loc.get_value(state)``
    """

    def __init__(self, ptr_loc, main_loc):
        super().__init__(ptr_loc.size)  # ???
        self.ptr_loc = ptr_loc
        self.main_loc = main_loc

    def get_footprint(self):
        yield from self.ptr_loc.get_footprint()

    def get_value(self, state, **kwargs):
        ptr_val = self.ptr_loc.get_value(state, **kwargs)
        return self.main_loc.get_value(state, stack_base=ptr_val, **kwargs)

    def set_value(self, state, value, **kwargs):
        ptr_val = self.ptr_loc.get_value(state, **kwargs)
        self.main_loc.set_value(state, value, stack_base=ptr_val, **kwargs)


class ArgSession:
    """
    A class to keep track of the state accumulated in laying parameters out into memory
    """

    __slots__ = (
        "cc",
        "fp_iter",
        "int_iter",
        "both_iter",
    )

    def __init__(self, cc):
        self.cc = cc
        self.fp_iter = cc.fp_args
        self.int_iter = cc.int_args
        self.both_iter = cc.memory_args

    def getstate(self):
        return (self.fp_iter.getstate(), self.int_iter.getstate(), self.both_iter.getstate())

    def setstate(self, state):
        fp, int_, both = state
        self.fp_iter.setstate(fp)
        self.int_iter.setstate(int_)
        self.both_iter.setstate(both)


class UsercallArgSession:
    """
    An argsession for use with SimCCUsercall
    """

    __slots__ = (
        "cc",
        "real_args",
    )

    def __init__(self, cc):
        self.cc = cc
        self.real_args = SerializableListIterator(self.cc.arg_locs)

    def getstate(self):
        return self.real_args.getstate()

    def setstate(self, state):
        self.real_args.setstate(state)


class SimCC:
    """
    A calling convention allows you to extract from a state the data passed from function to
    function by calls and returns. Most of the methods provided by SimCC that operate on a state
    assume that the program is just after a call but just before stack frame allocation, though
    this may be overridden with the `stack_base` parameter to each individual method.

    This is the base class for all calling conventions.
    """

    def __init__(self, arch: archinfo.Arch):
        """
        :param arch:        The Archinfo arch for this CC
        """
        self.arch = arch

    #
    # Here are all the things a subclass needs to specify!
    #

    ARG_REGS: List[str] = []  # A list of all the registers used for integral args, in order (names or offsets)
    FP_ARG_REGS: List[str] = []  # A list of all the registers used for floating point args, in order
    STACKARG_SP_BUFF = 0  # The amount of stack space reserved between the saved return address
    # (if applicable) and the arguments. Probably zero.
    STACKARG_SP_DIFF = 0  # The amount of stack space reserved for the return address
    CALLER_SAVED_REGS: List[str] = []  # Caller-saved registers
    RETURN_ADDR: SimFunctionArgument = None  # The location where the return address is stored, as a SimFunctionArgument
    RETURN_VAL: SimFunctionArgument = None  # The location where the return value is stored, as a SimFunctionArgument
    OVERFLOW_RETURN_VAL: Optional[SimFunctionArgument] = (
        None  # The second half of the location where a double-length return value is stored
    )
    FP_RETURN_VAL: Optional[SimFunctionArgument] = (
        None  # The location where floating-point argument return values are stored
    )
    ARCH = None  # The archinfo.Arch class that this CC must be used for, if relevant
    CALLEE_CLEANUP = False  # Whether the callee has to deallocate the stack space for the arguments

    STACK_ALIGNMENT = 1  # the alignment requirement of the stack pointer at function start BEFORE call

    #
    # Here are several things you MAY want to override to change your cc's convention
    #

    @property
    def int_args(self):
        """
        Iterate through all the possible arg positions that can only be used to store integer or pointer values.

        Returns an iterator of SimFunctionArguments
        """
        if self.ARG_REGS is None:
            raise NotImplementedError()
        return SerializableListIterator([SimRegArg(reg, self.arch.bytes) for reg in self.ARG_REGS])

    @property
    def memory_args(self):
        """
        Iterate through all the possible arg positions that can be used to store any kind of argument.

        Returns an iterator of SimFunctionArguments
        """
        start = self.STACKARG_SP_BUFF + self.STACKARG_SP_DIFF
        return SerializableCounter(start, self.arch.bytes, lambda offset: SimStackArg(offset, self.arch.bytes))

    @property
    def fp_args(self):
        """
        Iterate through all the possible arg positions that can only be used to store floating point values.

        Returns an iterator of SimFunctionArguments
        """
        if self.FP_ARG_REGS is None:
            raise NotImplementedError()
        return SerializableListIterator([SimRegArg(reg, self.arch.bytes) for reg in self.FP_ARG_REGS])

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

    ArgSession = ArgSession  # import this from global scope so SimCC subclasses can subclass it if they like

    def arg_session(self, ret_ty: Optional[SimType]):
        """
        Return an arg session.

        A session provides the control interface necessary to describe how integral and floating-point arguments are
        laid out into memory. The default behavior is that there are a finite list of int-only and fp-only argument
        slots, and an infinite number of generic slots, and when an argument of a given type is requested, the most
        slot available is used. If you need different behavior, subclass ArgSession.

        You need to provide the return type of the function in order to kick off an arg layout session.
        """
        session = self.ArgSession(self)
        if self.return_in_implicit_outparam(ret_ty):
            self.next_arg(session, SimTypePointer(SimTypeBottom()))
        return session

    def return_in_implicit_outparam(self, ty):
        return False

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

    def return_val(self, ty, perspective_returned=False):
        """
        The location the return value is stored, based on its type.
        """
        if ty._arch is None:
            ty = ty.with_arch(self.arch)
        if isinstance(ty, (SimStruct, SimUnion, SimTypeFixedSizeArray)):
            raise AngrTypeError(
                f"{self} doesn't know how to return aggregate types. Consider overriding return_val to "
                "implement its ABI logic"
            )
        if self.return_in_implicit_outparam(ty):
            if perspective_returned:
                ptr_loc = self.RETURN_VAL
            else:
                ptr_loc = self.next_arg(self.ArgSession(self), SimTypePointer(SimTypeBottom()))
            return SimReferenceArgument(
                ptr_loc, SimStackArg(0, ty.size // self.arch.byte_width, is_fp=isinstance(ty, SimTypeFloat))
            )

        if isinstance(ty, SimTypeFloat) and self.FP_RETURN_VAL is not None:
            return self.FP_RETURN_VAL.refine(size=ty.size // self.arch.byte_width, arch=self.arch, is_fp=True)

        if self.RETURN_VAL is None or isinstance(ty, SimTypeBottom):
            return None
        if ty.size > self.RETURN_VAL.size * self.arch.byte_width:
            return SimComboArg([self.RETURN_VAL, self.OVERFLOW_RETURN_VAL])
        return self.RETURN_VAL.refine(size=ty.size // self.arch.byte_width, arch=self.arch, is_fp=False)

    @property
    def return_addr(self):
        """
        The location the return address is stored.
        """
        return self.RETURN_ADDR

    def next_arg(self, session: ArgSession, arg_type: SimType):
        if isinstance(arg_type, (SimTypeArray, SimTypeFixedSizeArray)):  # hack
            arg_type = SimTypePointer(arg_type.elem_type).with_arch(self.arch)
        if isinstance(arg_type, (SimStruct, SimUnion, SimTypeFixedSizeArray)):
            raise TypeError(
                f"{self} doesn't know how to store aggregate type {type(arg_type)}. Consider overriding next_arg to "
                "implement its ABI logic"
            )
        if isinstance(arg_type, SimTypeBottom):
            # This is usually caused by failures or mistakes during type inference
            l.warning("Function argument type cannot be BOT. Treating it as a 32-bit int.")
            arg_type = SimTypeInt().with_arch(self.arch)
        is_fp = isinstance(arg_type, SimTypeFloat)
        size = arg_type.size // self.arch.byte_width
        try:
            if is_fp:
                arg = next(session.fp_iter)
            else:
                arg = next(session.int_iter)
        except StopIteration:
            try:
                arg = next(session.both_iter)
            except StopIteration:
                raise TypeError("Accessed too many arguments - exhausted all positions?")

        if size > arg.size:
            if isinstance(arg, SimStackArg):
                arg_size = arg.size
                locations = [arg]
                while arg_size < size:
                    next_arg = next(session.both_iter)
                    arg_size += next_arg.size
                    locations.append(next_arg)
                return SimComboArg(locations, is_fp=is_fp)
            raise ValueError(
                f"{self} doesn't know how to store large types. Consider overriding"
                " next_arg to implement its ABI logic"
            )
        return arg.refine(size, is_fp=is_fp, arch=self.arch)

    #
    # Useful functions!
    #

    @staticmethod
    def is_fp_value(val):
        return (
            isinstance(val, (float, claripy.ast.FP))
            or (isinstance(val, claripy.ast.Base) and val.op.startswith("fp"))
            or (isinstance(val, claripy.ast.Base) and val.op == "Reverse" and val.args[0].op.startswith("fp"))
        )

    @staticmethod
    def guess_prototype(args, prototype=None):
        """
        Come up with a plausible SimTypeFunction for the given args (as would be passed to e.g. setup_callsite).

        You can pass a variadic function prototype in the `base_type` parameter and all its arguments will be used,
        only guessing types for the variadic arguments.
        """
        if type(prototype) is str:
            prototype = parse_signature(prototype)
        elif prototype is None:
            l.warning("Guessing call prototype. Please specify prototype.")

        charp = SimTypePointer(SimTypeChar())
        result = prototype if prototype is not None else SimTypeFunction([], charp)
        for arg in args[len(result.args) :]:
            if type(arg) in (int, bytes, PointerWrapper):
                result.args.append(charp)
            elif type(arg) is float:
                result.args.append(SimTypeDouble())
            elif isinstance(arg, claripy.ast.BV):
                result.args.append(SimTypeNum(len(arg), False))
            elif isinstance(arg, claripy.ast.FP):
                if arg.sort == claripy.FSORT_FLOAT:
                    result.args.append(SimTypeFloat())
                elif arg.sort == claripy.FSORT_DOUBLE:
                    result.args.append(SimTypeDouble())
                else:
                    raise TypeError("WHAT kind of floating point is this")
            else:
                raise TypeError("Cannot guess FFI type for %s" % type(arg))

        return result

    def arg_locs(self, prototype) -> List[SimFunctionArgument]:
        if prototype._arch is None:
            prototype = prototype.with_arch(self.arch)
        session = self.arg_session(prototype.returnty)
        return [self.next_arg(session, arg_ty) for arg_ty in prototype.args]

    def get_args(self, state, prototype, stack_base=None):
        arg_locs = self.arg_locs(prototype)
        return [loc.get_value(state, stack_base=stack_base) for loc in arg_locs]

    def set_return_val(self, state, val, ty, stack_base=None, perspective_returned=False):
        loc = self.return_val(ty, perspective_returned=perspective_returned)
        loc.set_value(state, val, stack_base=stack_base)

    def setup_callsite(self, state, ret_addr, args, prototype, stack_base=None, alloc_base=None, grow_like_stack=True):
        """
        This function performs the actions of the caller getting ready to jump into a function.

        :param state:           The SimState to operate on
        :param ret_addr:        The address to return to when the called function finishes
        :param args:            The list of arguments that that the called function will see
        :param prototype:       The signature of the call you're making. Should include variadic args concretely.
        :param stack_base:      An optional pointer to use as the top of the stack, circa the function entry point
        :param alloc_base:      An optional pointer to use as the place to put excess argument data
        :param grow_like_stack: When allocating data at alloc_base, whether to allocate at decreasing addresses

        The idea here is that you can provide almost any kind of python type in `args` and it'll be translated to a
        binary format to be placed into simulated memory. Lists (representing arrays) must be entirely elements of the
        same type and size, while tuples (representing structs) can be elements of any type and size.
        If you'd like there to be a pointer to a given value, wrap the value in a `PointerWrapper`.

        If stack_base is not provided, the current stack pointer will be used, and it will be updated.
        If alloc_base is not provided, the stack base will be used and grow_like_stack will implicitly be True.

        grow_like_stack controls the behavior of allocating data at alloc_base. When data from args needs to be wrapped
        in a pointer, the pointer needs to point somewhere, so that data is dumped into memory at alloc_base. If you
        set alloc_base to point to somewhere other than the stack, set grow_like_stack to False so that sequential
        allocations happen at increasing addresses.
        """

        # STEP 0: clerical work

        allocator = AllocHelper(self.arch.bits)
        if type(prototype) is str:
            prototype = parse_signature(prototype, arch=self.arch)
        elif prototype._arch is None:
            prototype = prototype.with_arch(self.arch)

        #
        # STEP 1: convert all values into serialized form
        # this entails creating the vals list of simple values to store and also populating the allocator's
        # understanding of what aux data needs to be stored
        # This is also where we compute arg locations (arg_locs)
        #

        vals = [self._standardize_value(arg, ty, state, allocator.dump) for arg, ty in zip(args, prototype.args)]
        arg_locs = self.arg_locs(prototype)

        # step 1.5, gotta handle the SimReferenceArguments correctly
        for i, (loc, val) in enumerate(zip(arg_locs, vals)):
            if not isinstance(loc, SimReferenceArgument):
                continue
            dumped = allocator.dump(val, state, loc=val.main_loc)
            vals[i] = dumped
            arg_locs[i] = val.ptr_loc

        # step 1.75 allocate implicit outparam stuff
        if self.return_in_implicit_outparam(prototype.returnty):
            loc = self.return_val(prototype.returnty)
            assert isinstance(loc, SimReferenceArgument)
            # hack: because the allocator gives us a pointer that needs to be translated, we need to shove it into
            # the args list so it'll be translated and stored once everything is laid out
            vals.append(allocator.alloc(loc.main_loc.size))
            arg_locs.append(loc.ptr_loc)

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
            loc.set_value(state, val, stack_base=stack_base)
        self.return_addr.set_value(state, ret_addr, stack_base=stack_base)

    def teardown_callsite(self, state, return_val=None, prototype=None, force_callee_cleanup=False):
        """
        This function performs the actions of the callee as it's getting ready to return.
        It returns the address to return to.

        :param state:                   The state to mutate
        :param return_val:              The value to return
        :param prototype:                 The prototype of the given function
        :param force_callee_cleanup:    If we should clean up the stack allocation for the arguments even if it's not
                                        the callee's job to do so

        TODO: support the stack_base parameter from setup_callsite...? Does that make sense in this context?
        Maybe it could make sense by saying that you pass it in as something like the "saved base pointer" value?
        """
        if return_val is not None and not isinstance(prototype.returnty, SimTypeBottom):
            self.set_return_val(state, return_val, prototype.returnty)
            # ummmmmmmm hack
            loc = self.return_val(prototype.returnty)
            if isinstance(loc, SimReferenceArgument):
                self.RETURN_VAL.set_value(state, loc.ptr_loc.get_value(state))

        ret_addr = self.return_addr.get_value(state)

        if state.arch.sp_offset is not None:
            if force_callee_cleanup or self.CALLEE_CLEANUP:
                session = self.arg_session(prototype.returnty)
                if self.return_in_implicit_outparam(prototype.returnty):
                    extra = [self.return_val(prototype.returnty).ptr_loc]
                else:
                    extra = []
                state.regs.sp += self.stack_space(extra + [self.next_arg(session, x) for x in prototype.args])
            else:
                state.regs.sp += self.STACKARG_SP_DIFF

        return ret_addr

    #
    # Helper functions
    #

    @staticmethod
    def _standardize_value(arg, ty, state, alloc):
        if isinstance(arg, SimActionObject):
            return SimCC._standardize_value(arg.ast, ty, state, alloc)
        elif isinstance(arg, PointerWrapper):
            if not isinstance(ty, (SimTypePointer, SimTypeReference)):
                raise TypeError("Type mismatch: expected %s, got pointer-wrapper" % ty)

            if arg.buffer:
                if isinstance(arg.value, claripy.Bits):
                    real_value = arg.value.chop(state.arch.byte_width)
                elif type(arg.value) in (bytes, str):
                    real_value = claripy.BVV(arg.value).chop(8)
                else:
                    raise TypeError("PointerWrapper(buffer=True) can only be used with a bitvector or a bytestring")
            else:
                child_type = SimTypeArray(ty.pts_to) if type(arg.value) in (str, bytes, list) else ty.pts_to
                try:
                    real_value = SimCC._standardize_value(arg.value, child_type, state, alloc)
                except TypeError as e:  # this is a dangerous catch...
                    raise TypeError(
                        f"Failed to store pointer-wrapped data ({e.args[0]}). "
                        "Do you want a PointerWrapper(buffer=True)?"
                    ) from None
            return alloc(real_value, state)

        elif isinstance(arg, (str, bytes)):
            # sanitize the argument and request standardization again with SimTypeArray
            if type(arg) is str:
                arg = arg.encode()
            arg += b"\0"
            if isinstance(ty, SimTypePointer) and isinstance(ty.pts_to, SimTypeChar):
                pass
            elif isinstance(ty, SimTypeFixedSizeArray) and isinstance(ty.elem_type, SimTypeChar):
                if len(arg) > ty.length:
                    raise TypeError(f"String {repr(arg)} is too long for {ty}")
                arg = arg.ljust(ty.length, b"\0")
            elif isinstance(ty, SimTypeArray) and isinstance(ty.elem_type, SimTypeChar):
                if ty.length is not None:
                    if len(arg) > ty.length:
                        raise TypeError(f"String {repr(arg)} is too long for {ty}")
                    arg = arg.ljust(ty.length, b"\0")
            elif isinstance(ty, SimTypeString):
                if len(arg) > ty.length + 1:
                    raise TypeError(f"String {repr(arg)} is too long for {ty}")
                arg = arg.ljust(ty.length + 1, b"\0")
            else:
                raise TypeError("Type mismatch: Expected %s, got char*" % ty)
            val = SimCC._standardize_value(list(arg), SimTypeArray(SimTypeChar(), len(arg)), state, alloc)
            return val

        elif isinstance(arg, list):
            if isinstance(ty, (SimTypePointer, SimTypeReference)):
                ref = True
                subty = ty.pts_to
            elif isinstance(ty, SimTypeArray):
                ref = True
                subty = ty.elem_type
                if ty.length is not None:
                    if len(arg) != ty.length:
                        raise TypeError(f"Array {repr(arg)} is the wrong length for {ty}")
            else:
                raise TypeError("Type mismatch: Expected %s, got char*" % ty)

            val = [SimCC._standardize_value(sarg, subty, state, alloc) for sarg in arg]
            if ref:
                val = alloc(val, state)
            return val

        elif isinstance(arg, (tuple, dict, SimStructValue)):
            if not isinstance(ty, SimStruct):
                raise TypeError(f"Type mismatch: Expected {ty}, got {type(arg)} (i.e. struct)")
            if type(arg) is not SimStructValue:
                if len(arg) != len(ty.fields):
                    raise TypeError("Wrong number of fields in struct, expected %d got %d" % (len(ty.fields), len(arg)))
                arg = SimStructValue(ty, arg)
            return SimStructValue(
                ty, [SimCC._standardize_value(arg[field], ty.fields[field], state, alloc) for field in ty.fields]
            )

        elif isinstance(arg, int):
            if isinstance(ty, SimTypeFloat):
                return SimCC._standardize_value(float(arg), ty, state, alloc)

            val = state.solver.BVV(arg, ty.size)
            return val

        elif isinstance(arg, float):
            if isinstance(ty, SimTypeDouble):
                sort = claripy.FSORT_DOUBLE
            elif isinstance(ty, SimTypeFloat):
                sort = claripy.FSORT_FLOAT
            else:
                raise TypeError("Type mismatch: expected %s, got float" % ty)

            return claripy.FPV(arg, sort)

        elif isinstance(arg, claripy.ast.FP):
            if isinstance(ty, SimTypeFloat):
                if len(arg) != ty.size:
                    raise TypeError(f"Type mismatch: expected {ty}, got {arg.sort}")
                return arg
            if isinstance(ty, (SimTypeReg, SimTypeNum)):
                return arg.val_to_bv(ty.size, ty.signed)
            raise TypeError(f"Type mismatch: expected {ty}, got {arg.sort}")

        elif isinstance(arg, claripy.ast.BV):
            if isinstance(ty, (SimTypeReg, SimTypeNum)):
                if len(arg) != ty.size:
                    raise TypeError("Type mismatch: expected %s, got %d bits" % (ty, len(arg)))
                return arg
            if isinstance(ty, (SimTypeFloat)):
                raise TypeError(
                    "It's unclear how to coerce a bitvector to %s. "
                    "Do you want .raw_to_fp or .val_to_fp, and signed or unsigned?"
                )
            raise TypeError("Type mismatch: expected %s, got bitvector" % ty)

        else:
            raise TypeError("I don't know how to serialize %s." % repr(arg))

    def __repr__(self):
        return f"<{self.__class__.__name__}>"

    def __eq__(self, other):
        return isinstance(other, self.__class__)

    @classmethod
    def _match(cls, arch, args: List, sp_delta):
        if cls.ARCH is not None and not isinstance(
            arch, cls.ARCH
        ):  # pylint:disable=isinstance-second-argument-not-valid-type
            return False
        if sp_delta != cls.STACKARG_SP_DIFF:
            return False

        sample_inst = cls(arch)
        all_fp_args = list(sample_inst.fp_args)
        all_int_args = list(sample_inst.int_args)
        both_iter = sample_inst.memory_args
        some_both_args = [next(both_iter) for _ in range(len(args))]

        new_args = []
        for arg in args:
            if arg not in all_fp_args and arg not in all_int_args and arg not in some_both_args:
                if isinstance(arg, SimRegArg) and arg.reg_name in sample_inst.CALLER_SAVED_REGS:
                    continue
                return False
            new_args.append(arg)

        # update args (e.g., drop caller-saved register arguments)
        args.clear()
        args.extend(new_args)

        return True

    @staticmethod
    def find_cc(
        arch: "archinfo.Arch", args: List[SimFunctionArgument], sp_delta: int, platform: str = "Linux"
    ) -> Optional["SimCC"]:
        """
        Pinpoint the best-fit calling convention and return the corresponding SimCC instance, or None if no fit is
        found.

        :param arch:        An ArchX instance. Can be obtained from archinfo.
        :param args:        A list of arguments. It may be updated by the first matched calling convention to
                            remove non-argument arguments.
        :param sp_delta:    The change of stack pointer before and after the call is made.
        :return:            A calling convention instance, or None if none of the SimCC subclasses seems to fit the
                            arguments provided.
        """
        if arch.name not in CC:
            return None
        if platform not in CC[arch.name]:
            # fallback to default
            platform = "default"
        possible_cc_classes = CC[arch.name][platform]
        for cc_cls in possible_cc_classes:
            if cc_cls._match(arch, args, sp_delta):
                return cc_cls(arch)
        return None

    def get_arg_info(self, state, prototype):
        """
        This is just a simple wrapper that collects the information from various locations
        prototype is as passed to self.arg_locs and self.get_args
        :param angr.SimState state: The state to evaluate and extract the values from
        :return:    A list of tuples, where the nth tuple is (type, name, location, value) of the nth argument
        """

        argument_locations = self.arg_locs(prototype)
        argument_values = self.get_args(state, prototype)

        argument_types = prototype.args
        argument_names = prototype.arg_names if prototype.arg_names else ["unknown"] * len(prototype.args)
        return list(zip(argument_types, argument_names, argument_locations, argument_values))


class SimLyingRegArg(SimRegArg):
    """
    A register that LIES about the types it holds
    """

    def __init__(self, name, size=8):
        super().__init__(name, 8)
        self._real_size = size

    def get_value(self, state, **kwargs):  # pylint:disable=arguments-differ
        # val = super(SimLyingRegArg, self).get_value(state, **kwargs)
        val = state.registers.load(self.reg_name).raw_to_fp()
        if self._real_size == 4:
            val = claripy.fpToFP(claripy.fp.RM.RM_NearestTiesEven, val.raw_to_fp(), claripy.FSORT_FLOAT)
        return val

    def set_value(self, state, value, **kwargs):  # pylint:disable=arguments-differ,unused-argument
        value = self.check_value_set(value, state.arch)
        if self._real_size == 4:
            value = claripy.fpToFP(claripy.fp.RM.RM_NearestTiesEven, value.raw_to_fp(), claripy.FSORT_DOUBLE)
        state.registers.store(self.reg_name, value)
        # super(SimLyingRegArg, self).set_value(state, value, endness=endness, **kwargs)

    def refine(self, size, arch=None, offset=None, is_fp=None):
        return SimLyingRegArg(self.reg_name, size)


class SimCCUsercall(SimCC):
    def __init__(self, arch, args, ret_loc):
        super().__init__(arch)
        self.args = args
        self.ret_loc = ret_loc

    ArgSession = UsercallArgSession

    def next_arg(self, session, arg_type):
        return next(session.real_args)

    def return_val(self, ty, **kwargs):
        return self.ret_loc


class SimCCCdecl(SimCC):
    ARG_REGS = []  # All arguments are passed in stack
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 4  # Return address is pushed on to stack by call
    CALLER_SAVED_REGS = ["eax", "ecx", "edx"]
    RETURN_VAL = SimRegArg("eax", 4)
    OVERFLOW_RETURN_VAL = SimRegArg("edx", 4)
    FP_RETURN_VAL = SimLyingRegArg("st0")
    RETURN_ADDR = SimStackArg(0, 4)
    ARCH = archinfo.ArchX86

    def next_arg(self, session, arg_type):
        if isinstance(arg_type, (SimTypeArray, SimTypeFixedSizeArray)):  # hack
            arg_type = SimTypePointer(arg_type.elem_type).with_arch(self.arch)
        locs_size = 0
        byte_size = arg_type.size // self.arch.byte_width
        locs = []
        while locs_size < byte_size:
            locs.append(next(session.both_iter))
            locs_size += locs[-1].size

        return refine_locs_with_struct_type(self.arch, locs, arg_type)

    STRUCT_RETURN_THRESHOLD = 32

    def return_val(self, ty, perspective_returned=False):
        if ty._arch is None:
            ty = ty.with_arch(self.arch)
        if not isinstance(ty, SimStruct):
            return super().return_val(ty, perspective_returned)

        if ty.size > self.STRUCT_RETURN_THRESHOLD:
            # TODO this code is duplicated a ton of places. how should it be a function?
            byte_size = ty.size // self.arch.byte_width
            referenced_locs = [SimStackArg(offset, self.arch.bytes) for offset in range(0, byte_size, self.arch.bytes)]
            referenced_loc = refine_locs_with_struct_type(self.arch, referenced_locs, ty)
            if perspective_returned:
                ptr_loc = self.RETURN_VAL
            else:
                ptr_loc = SimStackArg(0, 4)
            reference_loc = SimReferenceArgument(ptr_loc, referenced_loc)
            return reference_loc

        return refine_locs_with_struct_type(self.arch, [self.RETURN_VAL, self.OVERFLOW_RETURN_VAL], ty)

    def return_in_implicit_outparam(self, ty):
        if isinstance(ty, SimTypeBottom):
            return False
        return isinstance(ty, SimStruct) and ty.size > self.STRUCT_RETURN_THRESHOLD


class SimCCMicrosoftCdecl(SimCCCdecl):
    STRUCT_RETURN_THRESHOLD = 64


class SimCCStdcall(SimCCMicrosoftCdecl):
    CALLEE_CLEANUP = True


class SimCCMicrosoftFastcall(SimCC):
    ARG_REGS = ["ecx", "edx"]  # Remaining arguments are passed in stack
    STACKARG_SP_DIFF = 4  # Return address is pushed on to stack by call
    RETURN_VAL = SimRegArg("eax", 4)
    RETURN_ADDR = SimStackArg(0, 4)
    ARCH = archinfo.ArchX86


class MicrosoftAMD64ArgSession:
    def __init__(self, cc):
        self.cc = cc
        self.int_iter = cc.int_args
        self.fp_iter = cc.fp_args
        self.both_iter = cc.memory_args


class SimCCMicrosoftAMD64(SimCC):
    ARG_REGS = ["rcx", "rdx", "r8", "r9"]
    FP_ARG_REGS = ["xmm0", "xmm1", "xmm2", "xmm3"]
    STACKARG_SP_DIFF = 8  # Return address is pushed on to stack by call
    STACKARG_SP_BUFF = 32  # 32 bytes of shadow stack space
    RETURN_VAL = SimRegArg("rax", 8)
    OVERFLOW_RETURN_VAL = SimRegArg("rdx", 8)
    FP_RETURN_VAL = SimRegArg("xmm0", 32)
    RETURN_ADDR = SimStackArg(0, 8)
    ARCH = archinfo.ArchAMD64
    STACK_ALIGNMENT = 16

    ArgSession = MicrosoftAMD64ArgSession

    def next_arg(self, session, arg_type):
        if isinstance(arg_type, (SimTypeArray, SimTypeFixedSizeArray)):  # hack
            arg_type = SimTypePointer(arg_type.elem_type).with_arch(self.arch)
        try:
            int_loc = next(session.int_iter)
            fp_loc = next(session.fp_iter)
        except StopIteration:
            int_loc = fp_loc = next(session.both_iter)

        byte_size = arg_type.size // self.arch.byte_width

        if isinstance(arg_type, SimTypeFloat):
            return fp_loc.refine(size=byte_size, is_fp=True, arch=self.arch)

        if byte_size <= int_loc.size:
            return int_loc.refine(size=byte_size, is_fp=False, arch=self.arch)

        referenced_locs = [SimStackArg(offset, self.arch.bytes) for offset in range(0, byte_size, self.arch.bytes)]
        referenced_loc = refine_locs_with_struct_type(self.arch, referenced_locs, arg_type)
        reference_loc = SimReferenceArgument(int_loc, referenced_loc)
        return reference_loc

    def return_in_implicit_outparam(self, ty):
        if isinstance(ty, SimTypeBottom):
            return False
        return not isinstance(ty, SimTypeFloat) and ty.size > 64


class SimCCSyscall(SimCC):
    """
    The base class of all syscall CCs.
    """

    ERROR_REG: SimRegArg = None
    SYSCALL_ERRNO_START = None

    @staticmethod
    def syscall_num(state) -> int:
        raise NotImplementedError()

    def linux_syscall_update_error_reg(self, state, expr):
        # special handling for Linux syscalls: on some architectures (mips/a3, powerpc/cr0_0) a bool indicating success
        # or failure of a system call is used as an error flag (0 for success, 1 for error). we have to set this
        if state.project is None or state.project.simos is None or state.project.simos.name != "Linux":
            return expr
        if type(expr) is int:
            expr = claripy.BVV(expr, state.arch.bits)
        try:
            expr = expr.ast
        except AttributeError:
            pass
        nbits = self.ERROR_REG.size * state.arch.byte_width
        error_cond = claripy.UGE(expr, self.SYSCALL_ERRNO_START)
        if state.solver.is_false(error_cond):
            # guaranteed no error
            error_reg_val = claripy.BVV(0, nbits)
        elif state.solver.is_true(error_cond):
            # guaranteed error
            error_reg_val = claripy.BVV(-1, nbits)
            expr = -expr
        else:
            # both are satisfied, handle gracefully
            error_reg_val = claripy.If(error_cond, claripy.BVV(-1, nbits), 0)
            expr = claripy.If(error_cond, -expr, expr)

        self.ERROR_REG.set_value(state, error_reg_val)
        return expr

    def set_return_val(self, state, val, ty, **kwargs):  # pylint:disable=arguments-differ
        if self.ERROR_REG is not None:
            val = self.linux_syscall_update_error_reg(state, val)
        super().set_return_val(state, val, ty, **kwargs)


class SimCCX86LinuxSyscall(SimCCSyscall):
    ARG_REGS = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg("eax", 4)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 4)
    ARCH = archinfo.ArchX86

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.eax


class SimCCX86WindowsSyscall(SimCCSyscall):
    # TODO: Make sure the information is correct
    ARG_REGS = []
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg("eax", 4)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 4)
    ARCH = archinfo.ArchX86

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.eax


class SimCCSystemVAMD64(SimCC):
    ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    FP_ARG_REGS = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"]
    STACKARG_SP_DIFF = 8  # Return address is pushed on to stack by call
    CALLER_SAVED_REGS = [
        "rdi",
        "rsi",
        "rdx",
        "rcx",
        "r8",
        "r9",
        "r10",
        "r11",
        "rax",
    ]
    RETURN_ADDR = SimStackArg(0, 8)
    RETURN_VAL = SimRegArg("rax", 8)
    OVERFLOW_RETURN_VAL = SimRegArg("rdx", 8)
    FP_RETURN_VAL = SimRegArg("xmm0", 128)
    OVERFLOW_FP_RETURN_VAL = SimRegArg("xmm1", 128)
    ARCH = archinfo.ArchAMD64
    STACK_ALIGNMENT = 16

    @classmethod
    def _match(cls, arch, args, sp_delta):
        if cls.ARCH is not None and not isinstance(arch, cls.ARCH):
            return False
        # if sp_delta != cls.STACKARG_SP_DIFF:
        #    return False

        sample_inst = cls(arch)
        all_fp_args = list(sample_inst.fp_args)
        all_int_args = list(sample_inst.int_args)
        both_iter = sample_inst.memory_args
        some_both_args = [next(both_iter) for _ in range(len(args))]

        for arg in args:
            ex_arg = arg
            # attempt to coerce the argument into a form that might show up in these lists
            if type(ex_arg) is SimRegArg:
                if ex_arg.reg_name not in arch.registers:
                    # danger!
                    # if the register name is a digit-only string, we use it as an offset
                    try:
                        regfile_offset = int(ex_arg.reg_name)
                    except ValueError:
                        return False
                else:
                    regfile_offset = arch.registers[ex_arg.reg_name][0]
                while regfile_offset not in arch.register_names:
                    regfile_offset -= 1
                ex_arg.reg_name = arch.register_names[regfile_offset]
                ex_arg.reg_offset = 0

            if ex_arg not in all_fp_args and ex_arg not in all_int_args and ex_arg not in some_both_args:
                if isinstance(arg, SimStackArg) and arg.stack_offset == 0:
                    continue  # ignore return address?
                return False

        return True

    # https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf
    # section 3.2.3
    def next_arg(self, session, arg_type):
        if isinstance(arg_type, (SimTypeArray, SimTypeFixedSizeArray)):  # hack
            arg_type = SimTypePointer(arg_type.elem_type).with_arch(self.arch)
        state = session.getstate()
        classification = self._classify(arg_type)
        try:
            mapped_classes = []
            for cls in classification:
                if cls == "SSEUP":
                    mapped_classes.append(mapped_classes[-1].sse_extend(self.arch.bytes))
                elif cls == "NO_CLASS":
                    raise NotImplementedError("Bug. Report to @rhelmot")
                elif cls == "MEMORY":
                    mapped_classes.append(next(session.both_iter))
                elif cls == "INTEGER":
                    mapped_classes.append(next(session.int_iter))
                elif cls == "SSE":
                    mapped_classes.append(next(session.fp_iter))
                else:
                    raise NotImplementedError("Bug. Report to @rhelmot")
        except StopIteration:
            session.setstate(state)
            mapped_classes = [next(session.both_iter) for _ in classification]

        return refine_locs_with_struct_type(self.arch, mapped_classes, arg_type)

    def return_val(self, ty: Optional[SimType], perspective_returned=False):
        if ty is None:
            return None
        if ty._arch is None:
            ty = ty.with_arch(self.arch)
        classification = self._classify(ty)
        if any(cls == "MEMORY" for cls in classification):
            assert all(cls == "MEMORY" for cls in classification)
            byte_size = ty.size // self.arch.byte_width
            referenced_locs = [SimStackArg(offset, self.arch.bytes) for offset in range(0, byte_size, self.arch.bytes)]
            referenced_loc = refine_locs_with_struct_type(self.arch, referenced_locs, ty)
            if perspective_returned:
                ptr_loc = self.RETURN_VAL
            else:
                ptr_loc = SimRegArg("rdi", 8)
            reference_loc = SimReferenceArgument(ptr_loc, referenced_loc)
            return reference_loc
        else:
            mapped_classes = []
            int_iter = iter([self.RETURN_VAL, self.OVERFLOW_RETURN_VAL])
            fp_iter = iter([self.FP_RETURN_VAL, self.OVERFLOW_FP_RETURN_VAL])
            for cls in classification:
                if cls == "SSEUP":
                    mapped_classes.append(mapped_classes[-1].sse_extend(self.arch.bytes))
                elif cls == "NO_CLASS":
                    raise NotImplementedError("Bug. Report to @rhelmot")
                elif cls == "INTEGER":
                    mapped_classes.append(next(int_iter))
                elif cls == "SSE":
                    mapped_classes.append(next(fp_iter))
                else:
                    raise NotImplementedError("Bug. Report to @rhelmot")

            return refine_locs_with_struct_type(self.arch, mapped_classes, ty)

    def return_in_implicit_outparam(self, ty):
        if isinstance(ty, SimTypeBottom):
            return False
        # :P
        return isinstance(self.return_val(ty), SimReferenceArgument)

    def _classify(self, ty, chunksize=None):
        if chunksize is None:
            chunksize = self.arch.bytes
        # treat BOT as INTEGER
        if isinstance(ty, SimTypeBottom):
            nchunks = 1
        else:
            nchunks = (ty.size // self.arch.byte_width + chunksize - 1) // chunksize
        if isinstance(ty, (SimTypeInt, SimTypeChar, SimTypePointer, SimTypeNum, SimTypeBottom, SimTypeReference)):
            return ["INTEGER"] * nchunks
        elif isinstance(ty, (SimTypeFloat,)):
            return ["SSE"] + ["SSEUP"] * (nchunks - 1)
        elif isinstance(ty, (SimStruct, SimTypeFixedSizeArray, SimUnion)):
            if ty.size > 512:
                return ["MEMORY"] * nchunks
            flattened = self._flatten(ty)
            if flattened is None:
                return ["MEMORY"] * nchunks
            result = ["NO_CLASS"] * nchunks
            for offset, subty_list in flattened.items():
                for subty in subty_list:
                    # is the smaller chunk size necessary? Genuinely unsure
                    subresult = self._classify(subty, chunksize=1)
                    idx_start = offset // chunksize
                    idx_end = (offset + (subty.size // self.arch.byte_width) - 1) // chunksize
                    for i, idx in enumerate(range(idx_start, idx_end + 1)):
                        subclass = subresult[i * chunksize]
                        result[idx] = self._combine_classes(result[idx], subclass)
            if any(subresult == "MEMORY" for subresult in result):
                return ["MEMORY"] * nchunks
            if nchunks > 2 and (result[0] != "SSE" or any(subresult != "SSEUP" for subresult in result[1:])):
                return ["MEMORY"] * nchunks
            for i in range(1, nchunks):
                if result[i] == "SSEUP" and result[i - 1] not in ("SSE", "SSEUP"):
                    result[i] = "SSE"
            return result
        else:
            raise NotImplementedError("Ummmmm... not sure what goes here. report bug to @rhelmot")

    def _flatten(self, ty) -> Optional[Dict[int, List[SimType]]]:
        result: Dict[int, List[SimType]] = defaultdict(list)
        if isinstance(ty, SimStruct):
            if ty.packed:
                return None
            for field, subty in ty.fields.items():
                offset = ty.offsets[field]
                subresult = self._flatten(subty)
                if subresult is None:
                    return None
                for suboffset, subsubty_list in subresult.items():
                    result[offset + suboffset] += subsubty_list
        elif isinstance(ty, SimTypeFixedSizeArray):
            subresult = self._flatten(ty.elem_type)
            if subresult is None:
                return None
            for suboffset, subsubty_list in subresult.items():
                for idx in range(ty.length):
                    # TODO I think we need an explicit stride field on array types
                    result[idx * ty.elem_type.size // self.arch.byte_width + suboffset] += subsubty_list
        elif isinstance(ty, SimUnion):
            for field, subty in ty.members.items():
                subresult = self._flatten(subty)
                if subresult is None:
                    return None
                for suboffset, subsubty_list in subresult.items():
                    result[suboffset] += subsubty_list
        else:
            result[0].append(ty)
        return result

    def _combine_classes(self, cls1, cls2):
        if cls1 == cls2:
            return cls1
        if cls1 == "NO_CLASS":
            return cls2
        if cls2 == "NO_CLASS":
            return cls1
        if cls1 == "MEMORY" or cls2 == "MEMORY":
            return "MEMORY"
        if cls1 == "INTEGER" or cls2 == "INTEGER":
            return "INTEGER"
        return "SSE"


class SimCCAMD64LinuxSyscall(SimCCSyscall):
    ARG_REGS = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
    RETURN_VAL = SimRegArg("rax", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)
    ARCH = archinfo.ArchAMD64
    CALLER_SAVED_REGS = ["rax", "rcx", "r11"]

    @staticmethod
    def _match(arch, args, sp_delta):  # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.rax


class SimCCAMD64WindowsSyscall(SimCCSyscall):
    # TODO: Make sure the information is correct
    ARG_REGS = []
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg("rax", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)
    ARCH = archinfo.ArchAMD64

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.rax


class SimCCARM(SimCC):
    ARG_REGS = ["r0", "r1", "r2", "r3"]
    FP_ARG_REGS = []  # regular arg regs are used as fp arg regs
    CALLER_SAVED_REGS = []
    RETURN_ADDR = SimRegArg("lr", 4)
    RETURN_VAL = SimRegArg("r0", 4)
    OVERFLOW_RETURN_VAL = SimRegArg("r1", 4)
    ARCH = archinfo.ArchARM

    # https://github.com/ARM-software/abi-aa/blob/60a8eb8c55e999d74dac5e368fc9d7e36e38dda4/aapcs32/aapcs32.rst#parameter-passing
    def next_arg(self, session, arg_type):
        if isinstance(arg_type, (SimTypeArray, SimTypeFixedSizeArray)):  # hack
            arg_type = SimTypePointer(arg_type.elem_type).with_arch(self.arch)
        state = session.getstate()
        classification = self._classify(arg_type)
        try:
            mapped_classes = []
            for cls in classification:
                if cls == "DOUBLEP":
                    if session.getstate()[1] % 2 == 1:  # doubles must start on an even register
                        next(session.int_iter)

                    if session.getstate()[1] == len(self.ARG_REGS) - 2:
                        mapped_classes.append(next(session.int_iter))
                        mapped_classes.append(next(session.both_iter))
                    else:
                        try:
                            mapped_classes.append(next(session.int_iter))
                            mapped_classes.append(next(session.int_iter))
                        except StopIteration:
                            mapped_classes.append(next(session.both_iter))
                            mapped_classes.append(next(session.both_iter))
                elif cls == "NO_CLASS":
                    raise NotImplementedError("Bug. Report to @rhelmot")
                elif cls == "MEMORY":
                    mapped_classes.append(next(session.both_iter))
                elif cls == "INTEGER":
                    try:
                        mapped_classes.append(next(session.int_iter))
                    except StopIteration:
                        mapped_classes.append(next(session.both_iter))
                elif cls == "SINGLEP":
                    try:
                        mapped_classes.append(next(session.int_iter))
                    except StopIteration:
                        mapped_classes.append(next(session.both_iter))
                else:
                    raise NotImplementedError("Bug. Report to @rhelmot")
        except StopIteration:
            session.setstate(state)
            mapped_classes = [next(session.both_iter) for _ in classification]

        return refine_locs_with_struct_type(self.arch, mapped_classes, arg_type)

    def _classify(self, ty, chunksize=None):
        if chunksize is None:
            chunksize = self.arch.bytes
        # treat BOT as INTEGER
        if isinstance(ty, SimTypeBottom):
            nchunks = 1
        else:
            nchunks = (ty.size // self.arch.byte_width + chunksize - 1) // chunksize
        if isinstance(ty, (SimTypeInt, SimTypeChar, SimTypePointer, SimTypeNum, SimTypeBottom, SimTypeReference)):
            return ["INTEGER"] * nchunks
        elif isinstance(ty, (SimTypeFloat,)):
            if ty.size == 64:
                return ["DOUBLEP"]
            elif ty.size == 32:
                return ["SINGLEP"]
            return ["NO_CLASS"]
        elif isinstance(ty, (SimStruct, SimTypeFixedSizeArray, SimUnion)):
            flattened = self._flatten(ty)
            if flattened is None:
                return ["MEMORY"] * nchunks
            result = ["NO_CLASS"] * nchunks
            for offset, subty_list in flattened.items():
                for subty in subty_list:
                    # is the smaller chunk size necessary? Genuinely unsure
                    subresult = self._classify(subty, chunksize=1)
                    idx_start = offset // chunksize
                    idx_end = (offset + (subty.size // self.arch.byte_width) - 1) // chunksize
                    for i, idx in enumerate(range(idx_start, idx_end + 1)):
                        subclass = subresult[i * chunksize]
                        result[idx] = self._combine_classes(result[idx], subclass)
            return result
        else:
            raise NotImplementedError("Ummmmm... not sure what goes here. report bug to @rhelmot")

    def _combine_classes(self, cls1, cls2):
        if cls1 == cls2:
            return cls1
        if cls1 == "NO_CLASS":
            return cls2
        if cls2 == "NO_CLASS":
            return cls1
        if cls1 == "MEMORY" or cls2 == "MEMORY":
            return "MEMORY"
        if cls1 == "INTEGER" or cls2 == "INTEGER":
            return "INTEGER"
        return "SSE"

    def _flatten(self, ty) -> Optional[Dict[int, List[SimType]]]:
        result: Dict[int, List[SimType]] = defaultdict(list)
        if isinstance(ty, SimStruct):
            if ty.packed:
                return None
            for field, subty in ty.fields.items():
                offset = ty.offsets[field]
                subresult = self._flatten(subty)
                if subresult is None:
                    return None
                for suboffset, subsubty_list in subresult.items():
                    result[offset + suboffset] += subsubty_list
        elif isinstance(ty, SimTypeFixedSizeArray):
            subresult = self._flatten(ty.elem_type)
            if subresult is None:
                return None
            for suboffset, subsubty_list in subresult.items():
                for idx in range(ty.length):
                    # TODO I think we need an explicit stride field on array types
                    result[idx * ty.elem_type.size // self.arch.byte_width + suboffset] += subsubty_list
        elif isinstance(ty, SimUnion):
            for field, subty in ty.members.items():
                subresult = self._flatten(subty)
                if subresult is None:
                    return None
                for suboffset, subsubty_list in subresult.items():
                    result[suboffset] += subsubty_list
        else:
            result[0].append(ty)
        return result


class SimCCARMHF(SimCCARM):
    ARG_REGS = ["r0", "r1", "r2", "r3"]
    FP_ARG_REGS = [f"s{i}" for i in range(16)]  # regular arg regs are used as fp arg regs
    FP_RETURN_VAL = SimRegArg("s0", 32)
    CALLER_SAVED_REGS = []
    RETURN_ADDR = SimRegArg("lr", 4)
    RETURN_VAL = SimRegArg("r0", 4)  # TODO Return val can also include reg r1
    ARCH = archinfo.ArchARMHF


class SimCCARMLinuxSyscall(SimCCSyscall):
    # TODO: Make sure all the information is correct
    ARG_REGS = ["r0", "r1", "r2", "r3"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_ADDR = SimRegArg("ip_at_syscall", 4)
    RETURN_VAL = SimRegArg("r0", 4)
    ARCH = archinfo.ArchARM

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        if ((state.regs.ip_at_syscall & 1) == 1).is_true():
            insn = state.mem[state.regs.ip_at_syscall - 3].short.resolved
            is_svc = ((insn & 0xFF00) == 0xDF00).is_true()
            svc_num = insn & 0xFF
        else:
            insn = state.mem[state.regs.ip_at_syscall - 4].dword.resolved
            is_svc = ((insn & 0x0F000000) == 0x0F000000).is_true()
            svc_num = insn & 0xFFFFFF
        if not is_svc:
            l.error("ARM syscall number being queried at an address which is not an SVC")
            return claripy.BVV(0, 32)

        if len(svc_num) == 32 and (svc_num > 0x900000).is_true() and (svc_num < 0x90FFFF).is_true():
            return svc_num - 0x900000
        else:
            return state.regs.r7


class SimCCAArch64(SimCC):
    ARG_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_ADDR = SimRegArg("lr", 8)
    RETURN_VAL = SimRegArg("x0", 8)
    ARCH = archinfo.ArchAArch64


class SimCCAArch64LinuxSyscall(SimCCSyscall):
    # TODO: Make sure all the information is correct
    ARG_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_VAL = SimRegArg("x0", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)
    ARCH = archinfo.ArchAArch64

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.x8


class SimCCRISCV64LinuxSyscall(SimCCSyscall):
    # TODO: Make sure all the information is correct
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_VAL = SimRegArg("a0", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 4)
    ARCH = archinfo.ArchRISCV64

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.a0


class SimCCO32(SimCC):
    ARG_REGS = ["a0", "a1", "a2", "a3"]
    FP_ARG_REGS = [
        "f12",
        "f13",
        "f14",
        "f15",
    ]  # Note double precision args are split between f12-f13, f14-f15 and single precision only use f12 and f14
    STACKARG_SP_BUFF = 16
    CALLER_SAVED_REGS = ["t9", "gp"]
    RETURN_ADDR = SimRegArg("ra", 4)
    RETURN_VAL = SimRegArg("v0", 4)
    OVERFLOW_RETURN_VAL = SimRegArg("v1", 4)
    ARCH = archinfo.ArchMIPS32

    # http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf Section 3-17
    def next_arg(self, session, arg_type):
        if isinstance(arg_type, (SimTypeArray, SimTypeFixedSizeArray)):  # hack
            arg_type = SimTypePointer(arg_type.elem_type).with_arch(self.arch)
        state = session.getstate()
        classification = self._classify(arg_type)
        try:
            mapped_classes = []
            can_use_fp = True
            for idx, cls in enumerate(classification):
                if cls == "DOUBLEP":
                    mapped_classes.append(next(session.fp_iter))
                    mapped_classes.append(next(session.fp_iter))
                    if isinstance(arg_type, SimStruct) and idx < 2 and can_use_fp:
                        next(session.fp_iter)  # consume next two fp regs since it's double precision
                        next(session.fp_iter)
                elif cls == "NO_CLASS":
                    raise NotImplementedError("Bug. Report to @rhelmot")
                elif cls == "MEMORY":
                    mapped_classes.append(next(session.both_iter))
                    can_use_fp = False
                elif cls == "INTEGER":
                    mapped_classes.append(next(session.int_iter))
                    can_use_fp = False
                elif cls == "SINGLEP":
                    if isinstance(arg_type, SimStruct):
                        if idx < 2 and can_use_fp:
                            mapped_classes.append(next(session.fp_iter))
                            next(session.int_iter)  # Need to take up the arg slot
                        else:
                            mapped_classes.append(next(session.both_iter))
                    else:
                        mapped_classes.append(next(session.fp_iter))
                        next(session.fp_iter)  # consume f13 or f15 since it's single precision

                else:
                    raise NotImplementedError("Bug. Report to @rhelmot")
        except StopIteration:
            session.setstate(state)
            mapped_classes = [next(session.both_iter) for _ in classification]

        return refine_locs_with_struct_type(self.arch, mapped_classes, arg_type)

    def _classify(self, ty, chunksize=None):
        if chunksize is None:
            chunksize = self.arch.bytes
        # treat BOT as INTEGER
        if isinstance(ty, SimTypeBottom):
            nchunks = 1
        else:
            nchunks = (ty.size // self.arch.byte_width + chunksize - 1) // chunksize
        if isinstance(ty, (SimTypeInt, SimTypeChar, SimTypePointer, SimTypeNum, SimTypeBottom, SimTypeReference)):
            return ["INTEGER"] * nchunks
        elif isinstance(ty, (SimTypeFloat,)):
            if ty.size == 64:
                return ["DOUBLEP"]
            elif ty.size == 32:
                return ["SINGLEP"]
            return ["NO_CLASS"]
        elif isinstance(ty, (SimStruct, SimTypeFixedSizeArray, SimUnion)):
            flattened = self._flatten(ty)
            if flattened is None:
                return ["MEMORY"] * nchunks
            result = ["NO_CLASS"] * nchunks
            for offset, subty_list in flattened.items():
                for subty in subty_list:
                    # is the smaller chunk size necessary? Genuinely unsure
                    subresult = self._classify(subty, chunksize=1)
                    idx_start = offset // chunksize
                    idx_end = (offset + (subty.size // self.arch.byte_width) - 1) // chunksize
                    for i, idx in enumerate(range(idx_start, idx_end + 1)):
                        subclass = subresult[i * chunksize]
                        result[idx] = self._combine_classes(result[idx], subclass)
            return result
        else:
            raise NotImplementedError("Ummmmm... not sure what goes here. report bug to @rhelmot")

    def _combine_classes(self, cls1, cls2):
        if cls1 == cls2:
            return cls1
        if cls1 == "NO_CLASS":
            return cls2
        if cls2 == "NO_CLASS":
            return cls1
        if cls1 == "MEMORY" or cls2 == "MEMORY":
            return "MEMORY"
        if cls1 == "INTEGER" or cls2 == "INTEGER":
            return "INTEGER"
        return "SSE"

    def _flatten(self, ty) -> Optional[Dict[int, List[SimType]]]:
        result: Dict[int, List[SimType]] = defaultdict(list)
        if isinstance(ty, SimStruct):
            if ty.packed:
                return None
            for field, subty in ty.fields.items():
                offset = ty.offsets[field]
                subresult = self._flatten(subty)
                if subresult is None:
                    return None
                for suboffset, subsubty_list in subresult.items():
                    result[offset + suboffset] += subsubty_list
        elif isinstance(ty, SimTypeFixedSizeArray):
            subresult = self._flatten(ty.elem_type)
            if subresult is None:
                return None
            for suboffset, subsubty_list in subresult.items():
                for idx in range(ty.length):
                    # TODO I think we need an explicit stride field on array types
                    result[idx * ty.elem_type.size // self.arch.byte_width + suboffset] += subsubty_list
        elif isinstance(ty, SimUnion):
            for field, subty in ty.members.items():
                subresult = self._flatten(subty)
                if subresult is None:
                    return None
                for suboffset, subsubty_list in subresult.items():
                    result[suboffset] += subsubty_list
        else:
            result[0].append(ty)
        return result


class SimCCO32LinuxSyscall(SimCCSyscall):
    # TODO: Make sure all the information is correct
    ARG_REGS = ["a0", "a1", "a2", "a3"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_VAL = SimRegArg("v0", 4)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 4)
    ARCH = archinfo.ArchMIPS32

    ERROR_REG = SimRegArg("a3", 4)
    SYSCALL_ERRNO_START = -1133

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.v0


class SimCCN64(SimCC):  # TODO: add n32
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    CALLER_SAVED_REGS = ["t9", "gp"]
    FP_ARG_REGS = []  # TODO: ???
    STACKARG_SP_BUFF = 32
    RETURN_ADDR = SimRegArg("ra", 8)
    RETURN_VAL = SimRegArg("v0", 8)
    ARCH = archinfo.ArchMIPS64


SimCCO64 = SimCCN64  # compatibility


class SimCCN64LinuxSyscall(SimCCSyscall):
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_VAL = SimRegArg("v0", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)
    ARCH = archinfo.ArchMIPS64

    ERROR_REG = SimRegArg("a3", 8)
    SYSCALL_ERRNO_START = -1133

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.v0


class SimCCPowerPC(SimCC):
    ARG_REGS = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    FP_ARG_REGS = []  # TODO: ???
    STACKARG_SP_BUFF = 8
    RETURN_ADDR = SimRegArg("lr", 4)
    RETURN_VAL = SimRegArg("r3", 4)
    ARCH = archinfo.ArchPPC32


class SimCCPowerPCLinuxSyscall(SimCCSyscall):
    # TODO: Make sure all the information is correct
    ARG_REGS = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg("r3", 4)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 4)
    ARCH = archinfo.ArchPPC32

    ERROR_REG = SimRegArg("cr0_0", 1)
    SYSCALL_ERRNO_START = -515

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.r0


class SimCCPowerPC64(SimCC):
    ARG_REGS = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    FP_ARG_REGS = []  # TODO: ???
    STACKARG_SP_BUFF = 0x70
    RETURN_ADDR = SimRegArg("lr", 8)
    RETURN_VAL = SimRegArg("r3", 8)
    ARCH = archinfo.ArchPPC64


class SimCCPowerPC64LinuxSyscall(SimCCSyscall):
    # TODO: Make sure all the information is correct
    ARG_REGS = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg("r3", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)
    ARCH = archinfo.ArchPPC64

    ERROR_REG = SimRegArg("cr0_0", 1)
    SYSCALL_ERRNO_START = -515

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

    def setup_callsite(self, state, ret_addr, args, prototype, stack_base=None, alloc_base=None, grow_like_stack=True):
        SootMixin.setup_callsite(state, args, ret_addr)

    @staticmethod
    def guess_prototype(args, prototype=None):
        # uhhhhhhhhhhhhhhhh
        return None


class SimCCUnknown(SimCC):
    """
    Represent an unknown calling convention.
    """

    @staticmethod
    def _match(arch, args, sp_delta):  # pylint: disable=unused-argument
        # It always returns True
        return True

    def __repr__(self):
        return f"<SimCCUnknown - {self.arch.name}>"


class SimCCS390X(SimCC):
    ARG_REGS = ["r2", "r3", "r4", "r5", "r6"]
    FP_ARG_REGS = ["f0", "f2", "f4", "f6"]
    STACKARG_SP_BUFF = 0xA0
    RETURN_ADDR = SimRegArg("r14", 8)
    RETURN_VAL = SimRegArg("r2", 8)
    ARCH = archinfo.ArchS390X


class SimCCS390XLinuxSyscall(SimCCSyscall):
    ARG_REGS = ["r2", "r3", "r4", "r5", "r6", "r7"]
    FP_ARG_REGS = []
    RETURN_VAL = SimRegArg("r2", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)
    ARCH = archinfo.ArchS390X

    @classmethod
    def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
        # never appears anywhere except syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.r1


CC: Dict[str, Dict[str, List[Type[SimCC]]]] = {
    "AMD64": {
        "default": [SimCCSystemVAMD64],
        "Linux": [SimCCSystemVAMD64],
        "Win32": [SimCCMicrosoftAMD64],
    },
    "X86": {
        "default": [SimCCCdecl],
        "Linux": [SimCCCdecl],
        "CGC": [SimCCCdecl],
        "Win32": [SimCCMicrosoftCdecl, SimCCMicrosoftFastcall],
    },
    "ARMEL": {
        "default": [SimCCARM],
        "Linux": [SimCCARM],
    },
    "ARMHF": {
        "default": [SimCCARMHF, SimCCARM],
        "Linux": [SimCCARMHF, SimCCARM],
    },
    "ARMCortexM": {
        "default": [SimCCARMHF, SimCCARM],
        "Linux": [SimCCARMHF, SimCCARM],
    },
    "MIPS32": {
        "default": [SimCCO32],
        "Linux": [SimCCO32],
    },
    "MIPS64": {
        "default": [SimCCN64],
        "Linux": [SimCCN64],
    },
    "PPC32": {
        "default": [SimCCPowerPC],
        "Linux": [SimCCPowerPC],
    },
    "PPC64": {
        "default": [SimCCPowerPC64],
        "Linux": [SimCCPowerPC64],
    },
    "AARCH64": {
        "default": [SimCCAArch64],
        "Linux": [SimCCAArch64],
    },
    "S390X": {
        "default": [SimCCS390X],
        "Linux": [SimCCS390X],
    },
}


DEFAULT_CC: Dict[str, Dict[str, Type[SimCC]]] = {
    "AMD64": {"Linux": SimCCSystemVAMD64, "Win32": SimCCMicrosoftAMD64},
    "X86": {"Linux": SimCCCdecl, "CGC": SimCCCdecl, "Win32": SimCCMicrosoftCdecl},
    "ARMEL": {"Linux": SimCCARM},
    "ARMHF": {"Linux": SimCCARMHF},
    "ARMCortexM": {"Linux": SimCCARM},
    "MIPS32": {"Linux": SimCCO32},
    "MIPS64": {"Linux": SimCCN64},
    "PPC32": {"Linux": SimCCPowerPC},
    "PPC64": {"Linux": SimCCPowerPC64},
    "AARCH64": {"Linux": SimCCAArch64},
    "Soot": {"Linux": SimCCSoot},
    "AVR8": {"Linux": SimCCUnknown},
    "MSP": {"Linux": SimCCUnknown},
    "S390X": {"Linux": SimCCS390X},
}


def register_default_cc(arch: str, cc: Type[SimCC], platform: str = "Linux"):
    DEFAULT_CC[arch] = {platform: cc}
    if arch not in CC:
        CC[arch] = {}
    if platform not in CC[arch]:
        CC[arch][platform] = [cc]
        if platform != "default":
            CC[arch]["default"] = [cc]
    else:
        if cc not in CC[arch][platform]:
            CC[arch][platform].append(cc)


ARCH_NAME_ALIASES = {
    "X86": ["x8632"],
    "AMD64": ["x86-64", "x86_64", "x8664"],
    "ARMEL": [],
    "ARMHF": [],
    "ARMCortexM": [],
    "AARCH64": ["arm64"],
    "MIPS32": [],
    "MIPS64": [],
    "PPC32": ["powerpc32"],
    "PPC64": ["powerpc64"],
    "Soot": [],
    "AVR8": [],
    "MSP": [],
    "S390X": [],
}

ALIAS_TO_ARCH_NAME = {}
for k, vs in ARCH_NAME_ALIASES.items():
    for v in vs:
        ALIAS_TO_ARCH_NAME[v] = k


def default_cc(  # pylint:disable=unused-argument
    arch: str,
    platform: Optional[str] = "Linux",
    language: Optional[str] = None,
    syscall: bool = False,
    **kwargs,
) -> Optional[Type[SimCC]]:
    """
    Return the default calling convention for a given architecture, platform, and language combination.

    :param arch:        The architecture name.
    :param platform:    The platform name (e.g., "Linux" or "Win32").
    :param language:    The programming language name (e.g., "go").
    :param syscall:     Return syscall convention (True), or normal calling convention (False, default).
    :return:            A default calling convention class if we can find one for the architecture, platform, and
                        language combination, or None if nothing fits.
    """

    if platform is None:
        platform = "Linux"

    default = kwargs.get("default", ...)
    cc_map = SYSCALL_CC if syscall else DEFAULT_CC

    if arch in cc_map:
        if platform not in cc_map[arch]:
            if default is not ...:
                return default
            if "Linux" in cc_map[arch]:
                return cc_map[arch]["Linux"]
        return cc_map[arch][platform]

    alias = unify_arch_name(arch)
    if alias not in cc_map or platform not in cc_map[alias]:
        if default is not ...:
            return default
    return cc_map[alias][platform]


def unify_arch_name(arch: str) -> str:
    """
    Return the unified architecture name.

    :param arch:    The architecture name.
    :return:        A unified architecture name.
    """

    if ":" in arch:
        # Sleigh architecture names
        chunks = arch.lower().split(":")
        if len(chunks) >= 3:
            arch_base, endianness, bits = chunks[:3]  # pylint:disable=unused-variable
            arch = f"{arch_base}{bits}"

    return ALIAS_TO_ARCH_NAME.get(arch, arch)


SYSCALL_CC: Dict[str, Dict[str, Type[SimCCSyscall]]] = {
    "X86": {
        "default": SimCCX86LinuxSyscall,
        "Linux": SimCCX86LinuxSyscall,
        "Win32": SimCCX86WindowsSyscall,
        "CGC": SimCCX86LinuxSyscall,
    },
    "AMD64": {
        "default": SimCCAMD64LinuxSyscall,
        "Linux": SimCCAMD64LinuxSyscall,
        "Win32": SimCCAMD64WindowsSyscall,
    },
    "ARMEL": {
        "default": SimCCARMLinuxSyscall,
        "Linux": SimCCARMLinuxSyscall,
    },
    "ARMCortexM": {
        # FIXME: TODO: This is wrong.  Fill in with a real CC when we support CM syscalls
        "default": SimCCARMLinuxSyscall,
    },
    "ARMHF": {
        "default": SimCCARMLinuxSyscall,
        "Linux": SimCCARMLinuxSyscall,
    },
    "AARCH64": {
        "default": SimCCAArch64LinuxSyscall,
        "Linux": SimCCAArch64LinuxSyscall,
    },
    "MIPS32": {
        "default": SimCCO32LinuxSyscall,
        "Linux": SimCCO32LinuxSyscall,
    },
    "MIPS64": {
        "default": SimCCN64LinuxSyscall,
        "Linux": SimCCN64LinuxSyscall,
    },
    "PPC32": {
        "default": SimCCPowerPCLinuxSyscall,
        "Linux": SimCCPowerPCLinuxSyscall,
    },
    "PPC64": {
        "default": SimCCPowerPC64LinuxSyscall,
        "Linux": SimCCPowerPC64LinuxSyscall,
    },
    "S390X": {
        "default": SimCCS390XLinuxSyscall,
        "Linux": SimCCS390XLinuxSyscall,
    },
    "RISCV64": {
        "default": SimCCRISCV64LinuxSyscall,
        "Linux": SimCCRISCV64LinuxSyscall,
    },
}


def register_syscall_cc(arch, os, cc):
    if arch not in SYSCALL_CC:
        SYSCALL_CC[arch] = {}
    SYSCALL_CC[arch][os] = cc


SyscallCC = SYSCALL_CC
DefaultCC = DEFAULT_CC
