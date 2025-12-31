from __future__ import annotations
import logging

import archinfo

from .resolver import IndirectJumpResolver

l = logging.getLogger(name=__name__)


class AArch64MachOGotResolver(IndirectJumpResolver):
    """
    A timeless indirect jump resolver that resolves GOT entries on AArch64 MachO binaries.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):  # pylint:disable=unused-argument
        if not isinstance(self.project.arch, archinfo.ArchAArch64):
            return False
        return jumpkind in ("Ijk_Boring", "Ijk_Call")

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):
        """
        Resolves the GOT entries in AARCH64 Mach-O binaries, where plt stubs are of manner::

        adrp    x16, #0x100000
        ldr     x16, [x16,#0x10]
        br      x16
        """

        insns = self.project.factory.block(block.addr, size=block.size).capstone.insns

        if len(insns) != 3:
            return False, []

        adrp_insn = None
        ldr_insn = None

        for i in range(len(insns) - 1):
            if (
                insns[i].mnemonic == "adrp"
                and insns[i + 1].mnemonic == "ldr"
                and "x16" in insns[i].op_str
                and "x16" in insns[i + 1].op_str
            ):
                adrp_insn = insns[i]
                ldr_insn = insns[i + 1]
                break

        if adrp_insn is None or ldr_insn is None:
            return False, []

        try:
            page_addr = adrp_insn.insn.operands[1].imm
            offset = ldr_insn.insn.operands[1].mem.disp
            slot = page_addr + offset
        except (AttributeError, IndexError):
            return False, []

        target = cfg._fast_memory_load_pointer(slot)
        if target is None:
            l.warning("Address %#x is not mapped.", slot)
            return False, []

        if self.project.loader.find_symbol(target):
            return True, [target]

        if not self.project.is_hooked(target):
            return False, []

        dest = self.project.hooked_by(target)
        l.debug("Resolved target to %s", dest.display_name)
        return True, [target]
