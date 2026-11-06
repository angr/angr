from __future__ import annotations

import logging

from archinfo import ArchPcode

from angr.calling_conventions import (
    DEFAULT_CC,
    ArgSession,
    SimCC,
    SimCCARM,
    SimCCO32,
    SimCCUnknown,
    SimFunctionArgument,
    SimRegArg,
    SimStackArg,
    default_cc,
    refine_locs_with_struct_type,
    register_default_cc,
)
from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeFixedSizeArray,
    SimTypeFloat,
    SimTypeNum,
    SimTypePointer,
    SimTypeReg,
    SimUnion,
    TypeRef,
)

l = logging.getLogger(__name__)


class SimCCPCodeBase(SimCC):
    """
    Base class for all pcode calling conventions.
    """

    LANGUAGE = None

    @classmethod
    def ARCH(cls):  # type: ignore
        assert cls.LANGUAGE is not None
        return ArchPcode(cls.LANGUAGE)


class SimCCM68k(SimCCPCodeBase):
    """
    Default CC for M68k
    """

    LANGUAGE = "68000:BE:32:default"
    ARG_REGS = []  # All arguments are passed in stack
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 4  # Return address is pushed on to stack by call
    RETURN_VAL = SimRegArg("d0", 4)
    RETURN_ADDR = SimStackArg(0, 4)


class SimCCRISCV(SimCCPCodeBase):
    """
    Default CC for RISCV
    """

    LANGUAGE = "RISCV:LE:32:RV32G"
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    RETURN_ADDR = SimRegArg("ra", 8)
    RETURN_VAL = SimRegArg("a0", 8)


class SimCCSPARC(SimCCPCodeBase):
    """
    Default CC for SPARC
    """

    LANGUAGE = "sparc:BE:32:default"
    ARG_REGS = ["o0", "o1", "o2", "o3", "o4", "o5"]
    RETURN_VAL = SimRegArg("o0", 8)
    RETURN_ADDR = SimRegArg("o7", 8)


class SimCCSH4(SimCCPCodeBase):
    """
    Default CC for SH4
    """

    LANGUAGE = "SuperH4:LE:32:default"
    # The SH ELF ABI passes the first four integer arguments in r4-r7.
    ARG_REGS = ["r4", "r5", "r6", "r7"]
    RETURN_VAL = SimRegArg("r0", 4)
    RETURN_ADDR = SimRegArg("pr", 4)

    def next_arg(self, session: ArgSession, arg_type: SimType) -> SimFunctionArgument:
        """
        Place an aggregate, or a scalar wider than one word, in consecutive word-sized slots.

        The slots come from the integer argument registers and then the stack, least significant word
        first, and an argument that outruns the registers takes the ones left and continues on the
        stack. Measured on SH objects built by gcc 10.5.0: a 64-bit second argument arrives in the
        pair r5:r6, with no alignment to an even register, and a 64-bit fourth argument arrives half
        in r7 and half in the first stack slot.

        A ``TypeRef`` is unwrapped first and laid out as the type it names, which is what
        :meth:`SimCC.next_arg` does with one: a typedef is where an opaque class or a 64-bit scalar
        usually hides, and delegating one would see it refused again.

        Anything one word or narrower goes to :meth:`SimCC.next_arg`, and so does any type this
        cannot lay out word by word -- a float, since this class declares no FP argument registers,
        and a type carrying no size, which the base class does not place either.
        """
        if isinstance(arg_type, TypeRef):  # a typedef is laid out as the type it names, as in SimCC.next_arg
            arg_type = arg_type.type
        if isinstance(arg_type, (SimTypeArray, SimTypeFixedSizeArray)):  # hack, the same one SimCC.next_arg applies
            arg_type = SimTypePointer(arg_type.elem_type).with_arch(self.arch)
        aggregate = isinstance(arg_type, (SimStruct, SimUnion))
        scalar = isinstance(arg_type, (SimTypeReg, SimTypeNum)) and not isinstance(arg_type, SimTypeFloat)
        if not (aggregate or scalar) or not arg_type.size:
            return super().next_arg(session, arg_type)
        size = arg_type.size // self.arch.byte_width
        if not size:
            # Narrower than a byte: the word count is zero, so the loop below would place nothing
            # and the argument would come back covering nothing at all. The base class refuses an
            # aggregate that shape and gives a narrow scalar a register of its own, which is what it
            # did before this override existed.
            return super().next_arg(session, arg_type)
        words = -(-size // self.arch.bytes)
        if words == 1 and not aggregate:
            return super().next_arg(session, arg_type)

        locs = []
        while len(locs) < words:
            try:
                locs.append(next(session.int_iter))
            except StopIteration:
                locs.append(next(session.both_iter))
        return refine_locs_with_struct_type(self.arch, locs, self._layout_type(arg_type))

    def _layout_type(self, arg_type: SimType) -> SimType:
        """
        The type to hand :func:`refine_locs_with_struct_type`, which is the argument's own unless
        that would lay out less of it than it occupies.

        The helper walks a struct field by field, and a union through whichever member spans it.
        Anything else it treats as one ``SimTypeInt``, which covers the first word and no more --
        while :meth:`next_arg` has taken a slot per word, so every word of the argument after the
        first would have no location at all. An opaque C++ class is exactly that shape: a size and
        no members.

        This catches the shape angr produces. It does not catch an aggregate whose own fields or
        members do not span it -- a union whose widest member is itself unlayoutable, a class with a
        size larger than its fields -- where the helper still covers less than the argument occupies.
        Nothing in angr builds either today.
        """
        if isinstance(arg_type, SimStruct) and not arg_type.fields:
            return SimTypeNum(arg_type.size, False).with_arch(self.arch)
        if isinstance(arg_type, SimUnion) and not any(
            member.size == arg_type.size for member in arg_type.members.values()
        ):
            return SimTypeNum(arg_type.size, False).with_arch(self.arch)
        return arg_type


class SimCCPARISC(SimCCPCodeBase):
    """
    Default CC for PARISC
    """

    LANGUAGE = "pa-risc:BE:32:default"
    ARG_REGS = ["r26", "r25"]
    RETURN_VAL = SimRegArg("r28", 4)
    RETURN_ADDR = SimRegArg("rp", 4)


class SimCCPowerPC(SimCCPCodeBase):
    """
    Default CC for PowerPC
    """

    LANGUAGE = "PowerPC:BE:32:e200"
    ARG_REGS = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    FP_ARG_REGS = []  # TODO: ???
    STACKARG_SP_BUFF = 8
    RETURN_ADDR = SimRegArg("lr", 4)
    RETURN_VAL = SimRegArg("r3", 4)


class SimCCXtensa(SimCCPCodeBase):
    """
    Default CC for Xtensa
    """

    LANGUAGE = "Xtensa:LE:32:default"
    ARG_REGS = ["a2", "a3", "a4", "a5", "a6", "a7"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_ADDR = SimRegArg("a0", 4)
    RETURN_VAL = SimRegArg("a2", 4)


def register_pcode_arch_default_cc(arch: ArchPcode):
    if arch.name not in DEFAULT_CC:
        # we have a bunch of manually specified mappings
        manual_cc_mapping = {
            "68000:BE:32:default": SimCCM68k,
            "ARM:LE:32:Cortex": SimCCARM,
            "RISCV:LE:32:RV32G": SimCCRISCV,
            "RISCV:LE:32:RV32GC": SimCCRISCV,
            "RISCV:LE:64:RV64G": SimCCRISCV,
            "RISCV:LE:64:RV64GC": SimCCRISCV,
            "sparc:BE:32:default": SimCCSPARC,
            "sparc:BE:64:default": SimCCSPARC,
            "SuperH4:LE:32:default": SimCCSH4,
            "pa-risc:BE:32:default": SimCCPARISC,
            "PowerPC:BE:32:e200": SimCCPowerPC,
            "PowerPC:BE:32:MPC8270": SimCCPowerPC,
            "Xtensa:LE:32:default": SimCCXtensa,
            "MIPS:LE:32:default": SimCCO32,
        }
        if arch.name in manual_cc_mapping:
            # first attempt: manually specified mappings
            cc = manual_cc_mapping[arch.name]
        else:
            # second attempt: see if there is a calling convention for a similar architecture defined in angr
            cc = default_cc(arch.name)
            if cc is None:
                # third attempt: use SimCCUnknown
                cc = SimCCUnknown

        if cc is SimCCUnknown:
            l.warning("Unknown default cc for arch %s", arch.name)
        register_default_cc(arch.name, cc)
