import claripy

from . import MemoryMixin


class ConditionalMixin(MemoryMixin):
    def load(self, addr, condition=None, fallback=None, **kwargs):
        res = super().load(addr, condition=condition, **kwargs)
        if condition is not None and fallback is not None:
            res = claripy.If(condition, res, fallback)
        return res

    def store(self, addr, data, size=None, condition=None, **kwargs):
        condition = self.state._adjust_condition(condition)

        if condition is None or self.state.solver.is_true(condition):
            super().store(addr, data, size=size, **kwargs)
            return
        if self.state.solver.is_false(condition):
            return

        default_data = super().load(addr, size=len(data) // self.state.arch.byte_width, **kwargs)
        conditional_data = claripy.If(condition, data, default_data)
        super().store(addr, conditional_data, size=size, **kwargs)
