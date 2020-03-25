import claripy

from . import MemoryMixin

class ConditionalStoreMixin(MemoryMixin):
    def store(self, addr, data, size=None, condition=None, **kwargs):
        if condition is None or self.state.solver.is_true(condition):
            super().store(addr, data, size=size, **kwargs)
            return
        if self.state.solver.is_false(condition):
            return

        default_data = super().load(addr, size=len(data) // self.state.arch.byte_width, **kwargs)
        conditional_data = claripy.If(condition, data, default_data)
        super().store(addr, conditional_data, size=size, **kwargs)
