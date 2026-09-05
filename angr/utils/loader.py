from __future__ import annotations

from typing import TYPE_CHECKING

import archinfo

if TYPE_CHECKING:
    from cle.backends.region import Region

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


def _region_permissions_are_known(region: Region) -> bool:
    """
    Check whether a cle region knows its own permissions.

    cle's base :class:`cle.backends.region.Region` answers True to all three permission questions so that
    SimOS has something to read. A blob's segments are plain ``Segment`` objects, so a blob claims read,
    write and execute over every byte of the file; read that as "no information" rather than as "writable".

    :param region:  The region to check.
    :return:        True if the region's permissions say something, False if they are cle's placeholder.
    """
    return not (region.is_readable and region.is_writable and region.is_executable)


def is_in_section(project: Project, addr: int) -> bool:
    """
    Check whether any section covers the specified address.

    :param project:     An angr Project instance.
    :param addr:        The address to check.
    :return:            True if a section contains the address, False otherwise.
    """
    return project.loader.find_section_containing(addr) is not None


def object_has_sections(project: Project, addr: int) -> bool:
    """
    Check whether the object containing the specified address publishes a section table at all.

    This separates an object that has sections and leaves a gap between them -- the file headers inside a
    read-only segment, for one -- from an object that has none, which is what cle's Blob backend produces.
    A caller that has to guess without sections should loosen only for the second.

    :param project:     An angr Project instance.
    :param addr:        The address to check.
    :return:            True if the object containing the address publishes sections.
    """
    obj = project.loader.find_object_containing(addr)
    return obj is not None and bool(obj.sections)


def is_readable_address(project: Project, addr: int) -> bool:
    """
    Check whether the specified address is mapped and readable.

    Falls back from sections to segments to plain mappedness, so this answers on an object that publishes
    no section table, where :func:`is_in_readonly_section` cannot.

    :param project:     An angr Project instance.
    :param addr:        The address to check.
    :return:            True if the address is readable, False otherwise.
    """
    loader = project.loader
    sec = loader.find_section_containing(addr)
    if sec is not None:
        return sec.is_readable
    seg = loader.find_segment_containing(addr)
    if seg is not None and _region_permissions_are_known(seg):
        return seg.is_readable
    return addr in loader.memory


def is_known_writable_address(project: Project, addr: int) -> bool:
    """
    Check whether the loader positively knows that the specified address is writable.

    This is not the negation of :func:`is_in_readonly_section`: an address whose permissions are unknown
    answers False, so a caller excluding mutable data does not thereby exclude every address in a blob.

    :param project:     An angr Project instance.
    :param addr:        The address to check.
    :return:            True if a section or an informative segment says the address is writable.
    """
    loader = project.loader
    sec = loader.find_section_containing(addr)
    if sec is not None:
        return sec.is_writable
    seg = loader.find_segment_containing(addr)
    if seg is not None and _region_permissions_are_known(seg):
        return seg.is_writable
    return False
