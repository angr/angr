from archinfo.arch_arm import is_arm_arch
from . import MemoryMixin

stn_map = { 'st%d' % n: n for n in range(8) }
tag_map = { 'tag%d' % n: n for n in range(8) }

class NameResolutionMixin(MemoryMixin):
    def _resolve_location_name(self, name, is_write=False):

        # Delayed load so SimMemory does not rely on SimEngines
        from ...engines.vex.ccall import _get_flags

        if self.category == 'reg':
            if self.state.arch.name in ('X86', 'AMD64'):
                if name in stn_map:
                    return (((stn_map[name] + self.load('ftop')) & 7) << 3) + self.state.arch.registers['fpu_regs'][0], 8
                elif name in tag_map:
                    return ((tag_map[name] + self.load('ftop')) & 7) + self.state.arch.registers['fpu_tags'][0], 1
                elif name in ('flags', 'eflags', 'rflags'):
                    # we tweak the state to convert the vex condition registers into the flags register
                    if not is_write:  # this work doesn't need to be done if we're just gonna overwrite it
                        self.store('cc_dep1', _get_flags(self.state)[0])  # constraints cannot be added by this
                    self.store('cc_op', 0) # OP_COPY
                    return self.state.arch.registers['cc_dep1'], self.state.arch.bytes
            if is_arm_arch(self.state.arch):
                if name == 'flags':
                    if not is_write:
                        self.store('cc_dep1', _get_flags(self.state)[0])
                    self.store('cc_op', 0)
                    return self.state.arch.registers['cc_dep1'], self.state.arch.bytes

            return self.state.arch.registers[name]
        elif name[0] == '*':
            return self.state.registers.load(name[1:]), None
        else:
            raise SimMemoryError("Trying to address memory with a register name.")

    def store(self, addr, data, size=None, **kwargs):
        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr, is_write=True)
            return super().store(named_addr, data, size=named_size if named_size is not None else size, **kwargs)
        else:
            return super().store(addr, data, size=size, **kwargs)

    def load(self, addr, size=None, **kwargs):
        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr, is_write=False)
            return super().load(named_addr, size=named_size if named_size is not None else size, **kwargs)
        else:
            return super().load(addr, size=size, **kwargs)


from ...errors import SimMemoryError
