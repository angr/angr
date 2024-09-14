from __future__ import annotations
from typing import TYPE_CHECKING

import archinfo

if TYPE_CHECKING:
    from angr import Project


def is_pc(project: Project, ins_addr: int, addr: int) -> bool:
    """
    Check if the given address is program counter (PC) or not. This function is for handling the case on some bizarre
    architectures where PC is always the currently executed instruction address plus a constant value.

    :param project:     An angr Project instance.
    :param ins_addr:    The address of an instruction. We calculate PC using this instruction address.
    :param addr:        The address to check against.
    :return:            True if the given instruction address is the PC, False otherwise.
    """
    if archinfo.arch_arm.is_arm_arch(project.arch):
        if ins_addr & 1 == 1:
            # thumb mode
            ins_addr = ins_addr - 1
            return addr == ins_addr + 4
        # arm mode
        return addr == ins_addr + 8
    return ins_addr == addr


def is_in_readonly_section(project: Project, addr: int) -> bool:
    """
    Check if the specified address is inside a read-only section.

    :param project:     An angr Project instance.
    :param addr:        The address to check.
    :return:            True if the given address belongs to a read-only section, False otherwise.
    """
    sec = project.loader.find_section_containing(addr)
    if sec is not None:
        return not sec.is_writable
    return False


def is_in_readonly_segment(project: Project, addr: int) -> bool:
    """
    Check if the specified address is inside a read-only segment.

    :param project:     An angr Project instance.
    :param addr:        The address to check.
    :return:            True if the given address belongs to a read-only segment, False otherwise.
    """
    seg = project.loader.find_segment_containing(addr)
    if seg is not None:
        return not seg.is_writable
    return False
