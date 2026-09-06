from __future__ import annotations

from typing import TYPE_CHECKING

from pyvex import IRSB
from pyvex.stmt import WrTmp

if TYPE_CHECKING:
    from collections.abc import Sequence

    import archinfo


def get_tmp_def_stmt(vex_block: IRSB, tmp_idx: int) -> int | None:
    for i, stmt in enumerate(vex_block.statements):
        if isinstance(stmt, WrTmp) and stmt.tmp == tmp_idx:
            return i
    return None


def block_branch_ins_addr(
    ins_addrs: Sequence[int], block_addr: int, block_size: int, arch: archinfo.Arch
) -> int | None:
    """
    Determine the address of the control-transfer instruction that ends a block.

    On architectures without delay slots, this is the last instruction of the block. On delay-slot
    architectures (MIPS), the block ends with the delay slot and the branch precedes it; depending
    on the lifter, the branch and its delay slot are recorded either as two IMarks (libVEX forks
    before Valgrind 3.27.1, pcode) or as a single IMark spanning both instructions (Valgrind
    3.27.1+), in which case the last recorded instruction address is the branch itself.

    :param ins_addrs:   Instruction addresses of the block (IMark start addresses).
    :param block_addr:  Address of the block.
    :param block_size:  Size of the block in bytes.
    :param arch:        The architecture.
    :return:            The branch instruction address, or None if ins_addrs is empty.
    """
    if not ins_addrs:
        return None
    last_ins_addr = ins_addrs[-1]
    if not arch.branch_delay_slot or len(ins_addrs) == 1:
        # without delay slots the last instruction ends the block; with delay slots, a
        # single-entry block is either a merged branch + delay-slot IMark (whose address is the
        # branch) or a lone instruction -- the only recorded address is correct either way
        return last_ins_addr
    if block_addr + block_size - last_ins_addr > last_ins_addr - ins_addrs[-2]:
        # the last IMark spans more bytes than a single instruction: the lifter merged the branch
        # and its delay slot into one IMark, whose address is the branch itself
        return last_ins_addr
    # the delay slot has its own IMark; the branch is the previous instruction
    return ins_addrs[-2]


def block_is_single_instruction(
    ins_addrs: Sequence[int], block_addr: int, block_size: int, arch: archinfo.Arch
) -> bool:
    """
    Determine whether a block holds at most one instruction, i.e. it is too short to carry a branch together with
    its delay slot. Only libVEX (Valgrind 3.27.1+) merges a branch and its delay slot into one IMark; such an IMark
    spans two fixed-width instructions, so on libVEX architectures a lone IMark counts as a single instruction only
    if it is no longer than one instruction.

    :param ins_addrs:   Instruction addresses of the block (IMark start addresses).
    :param block_addr:  Address of the block.
    :param block_size:  Size of the block in bytes.
    :param arch:        The architecture.
    :return:            True if the block holds at most one instruction.
    """
    if len(ins_addrs) > 1:
        return False
    if not ins_addrs:
        return True
    max_inst_bytes = getattr(arch, "max_inst_bytes", None)
    if getattr(arch, "vex_arch", None) is not None and max_inst_bytes:
        return block_addr + block_size - ins_addrs[0] <= max_inst_bytes
    return True
