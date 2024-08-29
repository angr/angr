from __future__ import annotations
import logging

from capstone.x86_const import X86_REG_RIP

from pyvex.stmt import IMark

from .resolver import IndirectJumpResolver

l = logging.getLogger(name=__name__)


class AMD64ElfGotResolver(IndirectJumpResolver):
    """
    A timeless indirect jump resolver that resolves GOT entries on AMD64 ELF binaries.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return jumpkind == "Ijk_Call" or jumpkind == "Ijk_Boring" and addr == func_addr

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):
        # Find the address and size of the last instruction
        last_insn_addr = None
        last_insn_size = None
        for stmt in reversed(block.statements):
            if isinstance(stmt, IMark):
                last_insn_addr = stmt.addr
                last_insn_size = stmt.len
                break

        if last_insn_addr is None:
            # Cannot find the last instruction
            return False, []

        # lift one instruction
        insn = self.project.factory.block(last_insn_addr, size=last_insn_size).capstone.insns[-1]
        opnd = insn.insn.operands[0]
        # Must be of the form: call [rip + 0xABCD]
        if not (opnd.mem and opnd.mem.disp and opnd.mem.base == X86_REG_RIP and not opnd.mem.index):
            return False, []

        disp = insn.insn.disp
        slot = disp + insn.address + insn.size
        target = cfg._fast_memory_load_pointer(slot)
        if target is None:
            l.warning("Address %# is not mapped.", slot)
            return False, []

        if self.project.loader.find_symbol(target):
            return True, [target]

        if not self.project.is_hooked(target):
            return False, []

        dest = self.project.hooked_by(target)
        l.debug("Resolved target to %s", dest.display_name)
        return True, [target]
