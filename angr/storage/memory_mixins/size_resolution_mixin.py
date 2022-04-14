from typing import Optional
import logging

from . import MemoryMixin
from ...errors import SimMemoryLimitError, SimMemoryError, SimUnsatError

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
        if out_size == 0:
            # skip zero-sized stores
            return

        super().store(addr, data, size=out_size, **kwargs)


class SizeConcretizationMixin(MemoryMixin):
    """
    This mixin allows memory to process symbolic sizes. It will not touch any sizes which are not ASTs with non-BVV ops.
    Assumes that the data is a BV.

    - symbolic load sizes will be concretized as their maximum and a warning will be logged
    - symbolic store sizes will be dispatched as several conditional stores with concrete sizes
    """
    def __init__(self, concretize_symbolic_write_size: bool=False, max_concretize_count: Optional[int]=256,
                 max_symbolic_size: int=0x400000, raise_memory_limit_error: bool=False, size_limit: int=257, **kwargs):
        super().__init__(**kwargs)
        self._concretize_symbolic_write_size = concretize_symbolic_write_size  # in place of the state option CONCRETIZE_SYMBOLIC_WRITE_SIZES
        self._max_concretize_count = max_concretize_count
        self._max_symbolic_size = max_symbolic_size
        self._raise_memory_limit_error = raise_memory_limit_error
        self._size_limit = size_limit

    def copy(self, memo):
        o = super().copy(memo)

        o._concretize_symbolic_write_size = self._concretize_symbolic_write_size
        o._max_concretize_count = self._max_concretize_count
        o._max_symbolic_size = self._max_symbolic_size
        o._raise_memory_limit_error = self._raise_memory_limit_error
        o._size_limit = self._size_limit

        return o

    def load(self, addr, size=None, **kwargs):
        if getattr(size, 'op', 'BVV') == 'BVV':
            return super().load(addr, size=size, **kwargs)

        l.warning("Loading symbolic size via max. be careful.")
        out_size = self.state.solver.max(size)
        return super().load(addr, size=out_size, **kwargs)

    def store(self, addr, data, size=None, condition=None, **kwargs):
        if getattr(size, 'op', 'BVV') == 'BVV':
            super().store(addr, data, size=size, condition=condition, **kwargs)
            return

        max_size = len(data) // self.state.arch.byte_width
        try:
            if self._raise_memory_limit_error:
                conc_sizes = list(self.state.solver.eval_upto(
                    size,
                    self._size_limit,
                    extra_constraints=(size <= max_size,)
                    )
                )
                if len(conc_sizes) == self._size_limit:
                    raise SimMemoryLimitError("Extremely unconstrained store size")
            else:
                conc_sizes = list(self.state.solver.eval_upto(
                    size,
                    self._max_concretize_count,
                    extra_constraints=(size <= max_size,)
                    )
                )
        except SimUnsatError:
            # size has to be greater than max_size
            raise SimMemoryError("Not enough data for store")

        # filter out all concrete sizes that are greater than max_size
        # Note that the VSA solver (used in static mode) cannot precisely handle extra constraints. As a result, we may
        # get conc_sizes with values that violate the extra constraint (size <= max_size).
        conc_sizes = [ cs for cs in conc_sizes if cs <= max_size ]
        conc_sizes.sort()
        if not conc_sizes:
            raise SimMemoryError("Not enough data for store")
        if self._max_concretize_count is not None:
            conc_sizes = conc_sizes[:self._max_concretize_count]

        if size.symbolic:
            if any(cs > self._max_symbolic_size for cs in conc_sizes):
                l.warning("At least one concretized size is over the limit of %d bytes. Constrain them to the limit.",
                        self._max_symbolic_size)
            conc_sizes = [min(cs, self._max_symbolic_size) for cs in conc_sizes]

        if condition is None:
            condition = self.state.solver.true
        for conc_size in conc_sizes:
            if conc_size == 0:
                continue
            super().store(addr, data, size=conc_size, condition=condition & (size == conc_size), **kwargs)


