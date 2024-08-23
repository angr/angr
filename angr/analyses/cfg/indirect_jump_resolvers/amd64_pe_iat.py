from __future__ import annotations
import logging

from capstone.x86_const import X86_OP_MEM, X86_REG_RIP

from ....simos import SimWindows
from .resolver import IndirectJumpResolver

l = logging.getLogger(name=__name__)


class AMD64PeIatResolver(IndirectJumpResolver):
    """
    A timeless indirect call/jump resolver for IAT in amd64 PEs.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not isinstance(self.project.simos, SimWindows):
            return False
        if jumpkind not in {"Ijk_Call", "Ijk_Boring"}:
            return False

        insns = self.project.factory.block(addr).capstone.insns
        if not insns:
            return False
        if not insns[-1].insn.operands:
            return False

        opnd = insns[-1].insn.operands[0]
        # Must be of the form: call qword ptr [0xABCD]
        return bool(opnd.type == X86_OP_MEM and opnd.mem.disp and opnd.mem.base == X86_REG_RIP and opnd.mem.index == 0)

    def resolve(
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):  # pylint:disable=unused-argument
        call_insn = self.project.factory.block(addr).capstone.insns[-1].insn
        addr = (call_insn.disp + call_insn.address + call_insn.size) & 0xFFFF_FFFF_FFFF_FFFF
        target = cfg._fast_memory_load_pointer(addr)
        if target is None:
            l.warning("Address %#x does not appear to be mapped", addr)
            return False, []

        if not self.project.is_hooked(target):
            return False, []

        dest = self.project.hooked_by(target)
        l.debug("Resolved target to %s", dest.display_name)
        return True, [target]
