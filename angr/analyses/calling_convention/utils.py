from __future__ import annotations
import logging

import archinfo
from archinfo.arch_arm import is_arm_arch, ArchARMHF, ArchARMCortexM

from angr.calling_conventions import SimCC

l = logging.getLogger(__name__)


def is_sane_register_variable(
    arch: archinfo.Arch, reg_offset: int, reg_size: int, def_cc: SimCC | type[SimCC] | None = None
) -> bool:
    """
    Filters all registers that are surly not members of function arguments.
    This can be seen as a workaround, since VariableRecoveryFast sometimes gives input variables of cc_ndep (which
    is a VEX-specific register) :-(

    :param reg_offset:  The register offset.
    :param reg_size:    The register size.
    :return:            True if it is an acceptable function argument, False otherwise.
    :rtype:             bool
    """

    arch_name = arch.name
    if ":" in arch_name:
        # for pcode architectures, we only leave registers that are known to be used as input arguments
        if def_cc is not None:
            return arch.translate_register_name(reg_offset, size=reg_size) in def_cc.ARG_REGS
        return True

    # VEX
    if arch_name == "AARCH64":
        return 16 <= reg_offset < 80  # x0-x7

    if arch_name == "AMD64":
        # TODO is rbx ever a register?
        return 24 <= reg_offset < 40 or 64 <= reg_offset < 104  # rcx, rdx  # rsi, rdi, r8, r9, r10
        # 224 <= reg_offset < 480)  # xmm0-xmm7

    if is_arm_arch(arch):
        if isinstance(arch, (ArchARMHF, ArchARMCortexM)):
            return 8 <= reg_offset < 24 or 128 <= reg_offset < 160  # r0 - 32  # s0 - s7, or d0 - d4
        return 8 <= reg_offset < 24  # r0-r3

    if arch_name == "MIPS32":
        return 24 <= reg_offset < 40  # a0-a3

    if arch_name == "MIPS64":
        return 48 <= reg_offset < 80 or 112 <= reg_offset < 208  # a0-a3 or t4-t7

    if arch_name == "PPC32":
        return 28 <= reg_offset < 60  # r3-r10

    if arch_name == "X86":
        return 8 <= reg_offset < 24 or 160 <= reg_offset < 288  # eax, ebx, ecx, edx  # xmm0-xmm7

    l.critical("Unsupported architecture %s.", arch.name)
    return True
