from __future__ import annotations
from . import MemoryMixin
from ... import sim_options as options


class SimplificationMixin(MemoryMixin):
    def store(self, addr, data, **kwargs):
        if (self.category == "mem" and options.SIMPLIFY_MEMORY_WRITES in self.state.options) or (
            self.category == "reg" and options.SIMPLIFY_REGISTER_WRITES in self.state.options
        ):
            real_data = self.state.solver.simplify(data)
        else:
            real_data = data
        super().store(addr, real_data, **kwargs)
