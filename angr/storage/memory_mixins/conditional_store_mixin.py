import claripy

from . import MemoryMixin

class ConditionalStoreMixin(MemoryMixin):
    def store(self, addr, data, condition=None, **kwargs):
        if self.state.solver.is_false(condition):
            return
        if self.state.solver.is_true(condition):
            super().store(addr, data, **kwargs)
            return

        default_data = super().load(addr, **kwargs)
        conditional_data = claripy.If(condition, data, default_data)
        super().store(addr, conditional_data, **kwargs)
