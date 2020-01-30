import logging

from . import MemoryMixin
from ...errors import SimMemoryLimitError, SimMemoryError

l = logging.getLogger(__name__)

class SizeNormalizationMixin(MemoryMixin):
    """
    Provides basic services related to normalizing sizes. After this mixin, sizes will always be a plain int.
    Assumes that the data is a BV.

    - load will throw a TypeError if no size is provided
    - store will default to len(data)//byte_width if no size is provided
    """
    def load(self, addr, size=None, **kwargs):
        if size is None:
            raise TypeError("Must provide size to load")
        elif type(size) is int:
            out_size = size
        elif getattr(size, 'op', None) == 'BVV':
            out_size = size.args[0]
        else:
            raise Exception("Size must be concretely resolved by this point in the memory stack")

        return super().load(addr, size=out_size, **kwargs)

    def store(self, addr, data, size=None, **kwargs):
        max_size = len(data) // self.state.arch.byte_width
        if size is None:
            out_size = max_size
        elif type(size) is int:
            out_size = size
        elif getattr(size, 'op', None) == 'BVV':
            out_size = size.args[0]
        else:
            raise Exception("Size must be concretely resolved by this point in the memory stack")

        if out_size > max_size:
            raise SimMemoryError("Not enough data for store")

        super().store(addr, data, size=out_size, **kwargs)

class SizeConcretizationMixin(MemoryMixin):
    """
    This mixin allows memory to process symbolic sizes. It will not touch any sizes which are not ASTs with non-BVV ops.
    Assumes that the data is a BV.

    - symbolic load sizes will be concretized as their maximum and a warning will be logged
    - symbolic store sizes will be dispatched as several conditional stores with concrete sizes
    """
    def load(self, addr, size=None, **kwargs):
        if getattr(size, 'op', 'BVV') != 'BVV':
            return super().load(addr, size=size, **kwargs)

        if getattr(size, 'op', 'BVV') != 'BVV':
            l.warning("Loading symbolic size via max. be careful.")
            out_size = self.state.solver.max(size)
        else:
            out_size = size
        return super().load(addr, size=out_size, **kwargs)

    def store(self, addr, data, size=None, condition=None, **kwargs):
        if getattr(size, 'op', 'BVV') != 'BVV':
            super().store(addr, data, size=size, **kwargs)
            return

        max_size = len(data) // self.state.arch.byte_width
        conc_sizes = list(self.state.solver.eval_upto(size, 257))
        if len(conc_sizes) == 257:
            raise SimMemoryLimitError("Extremely unconstrained store size")
        conc_sizes.sort()
        if conc_sizes[-1] > max_size:
            raise SimMemoryError("Not enough data for store")

        if condition is None:
            condition = self.state.solver.true
        for conc_size in conc_sizes:
            super().store(addr, data, size=conc_size, condition=condition & (size == conc_size), **kwargs)


