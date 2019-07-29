
import logging

from capstone.x86_const import X86_REG_RIP

from .resolver import IndirectJumpResolver

l = logging.getLogger(name=__name__)


class AMD64ElfGotResolver(IndirectJumpResolver):
    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if jumpkind != "Ijk_Call":
            return False

        opnd = self.project.factory.block(addr).capstone.insns[-1].insn.operands[0]
        # Must be of the form: call [rip + 0xABCD]
        if opnd.mem and opnd.mem.disp and opnd.mem.base == X86_REG_RIP and not opnd.mem.index:
            return True
        return False

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        insn = self.project.factory.block(addr).capstone.insns[-1]
        disp = insn.insn.disp
        slot = disp + insn.address + insn.size
        target = cfg._fast_memory_load_pointer(slot)
        if target is None:
            l.warning("Address %# is not mapped.", slot)
            return False, [ ]

        if not self.project.is_hooked(target):
            return False, [ ]

        dest = self.project.hooked_by(target)
        l.debug("Resolved target to %s", dest.display_name)
        return True, [target]
