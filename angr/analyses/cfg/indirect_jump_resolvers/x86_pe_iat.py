import logging

from capstone.x86_const import X86_OP_MEM

from ....simos import SimWindows
from .resolver import IndirectJumpResolver

l = logging.getLogger(name=__name__)


class X86PeIatResolver(IndirectJumpResolver):
    """
    A timeless indirect jump resolver for IAT in x86 PEs.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not isinstance(self.project.simos, SimWindows):
            return False
        if jumpkind != "Ijk_Call":
            return False

        insns = self.project.factory.block(addr).capstone.insns
        if not insns:
            return False
        if not insns[-1].insn.operands:
            return False

        opnd = insns[-1].insn.operands[0]
        # Must be of the form: call ds:0xABCD
        if opnd.type == X86_OP_MEM and opnd.mem.disp and not opnd.mem.base and not opnd.mem.index:
            return True
        return False

    def resolve(
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):  # pylint:disable=unused-argument
        slot = self.project.factory.block(addr).capstone.insns[-1].insn.disp
        target = cfg._fast_memory_load_pointer(slot)
        if target is None:
            l.warning("Address %#x does not appear to be mapped", slot)
            return False, []

        if not self.project.is_hooked(target):
            return False, []

        dest = self.project.hooked_by(target)
        l.debug("Resolved target to %s", dest.display_name)
        return True, [target]
