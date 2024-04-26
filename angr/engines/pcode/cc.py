import logging

from archinfo import ArchPcode

from ...calling_conventions import (
    SimCC,
    SimRegArg,
    SimStackArg,
    DEFAULT_CC,
    register_default_cc,
    SimCCUnknown,
    default_cc,
)


l = logging.getLogger(__name__)


class SimCCM68k(SimCC):
    """
    Default CC for M68k
    """

    ARG_REGS = []  # All arguments are passed in stack
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 4  # Return address is pushed on to stack by call
    RETURN_VAL = SimRegArg("d0", 4)
    RETURN_ADDR = SimStackArg(0, 4)


class SimCCRISCV(SimCC):
    """
    Default CC for RISCV
    """

    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    RETURN_ADDR = SimRegArg("ra", 8)
    RETURN_VAL = SimRegArg("a0", 8)


class SimCCSPARC(SimCC):
    """
    Default CC for SPARC
    """

    ARG_REGS = ["o0", "o1", "o2", "o3", "o4", "o5"]
    RETURN_VAL = SimRegArg("o0", 8)
    RETURN_ADDR = SimRegArg("o7", 8)


class SimCCSH4(SimCC):
    """
    Default CC for SH4
    """

    ARG_REGS = ["r4", "r5"]
    RETURN_VAL = SimRegArg("r0", 4)
    RETURN_ADDR = SimRegArg("pr", 4)


class SimCCPARISC(SimCC):
    """
    Default CC for PARISC
    """

    ARG_REGS = ["r26", "r25"]
    RETURN_VAL = SimRegArg("r28", 4)
    RETURN_ADDR = SimRegArg("rp", 4)


class SimCCPowerPC(SimCC):
    """
    Default CC for PowerPC
    """

    ARG_REGS = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    FP_ARG_REGS = []  # TODO: ???
    STACKARG_SP_BUFF = 8
    RETURN_ADDR = SimRegArg("lr", 4)
    RETURN_VAL = SimRegArg("r3", 4)


class SimCCXtensa(SimCC):
    """
    Default CC for Xtensa
    """

    ARG_REGS = ["i2", "i3", "i4", "i5", "i6", "i7"]
    FP_ARG_REGS = []  # TODO: ???
    RETURN_ADDR = SimRegArg("a0", 4)
    RETURN_VAL = SimRegArg("o2", 4)


def register_pcode_arch_default_cc(arch: ArchPcode):
    if arch.name not in DEFAULT_CC:
        # we have a bunch of manually specified mappings
        manual_cc_mapping = {
            "68000:BE:32:default": SimCCM68k,
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
