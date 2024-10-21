from __future__ import annotations

from angr import sim_options as options
from angr.storage.memory_mixins.memory_mixin import MemoryMixin


class SimplificationMixin(MemoryMixin):
    def store(self, addr, data, size=None, **kwargs):
        if (self.category == "mem" and options.SIMPLIFY_MEMORY_WRITES in self.state.options) or (
            self.category == "reg" and options.SIMPLIFY_REGISTER_WRITES in self.state.options
        ):
            real_data = self.state.solver.simplify(data)
        else:
            real_data = data
        super().store(addr, real_data, size, **kwargs)
