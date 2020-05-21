from typing import Dict, Optional

import claripy

from ..paged_memory.paged_memory_mixin import PagedMemoryMixin
from .region import MemoryRegion


class RegionedMemoryMixin(PagedMemoryMixin):
    """
    Regioned memory.
    It maps memory addresses into different pages.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._regions: Dict[MemoryRegion] = { }

    def load(self, addr, size: Optional[int]=None, endness=None, **kwargs):
        raise NotImplementedError()

    def store(self, addr, data, size: Optional[int]=None, endness=None, **kwargs):
        raise NotImplementedError()

    #
    # Private methods
    #

    def _normalize_address(self, addr: claripy.ast.Base, is_write: bool=False, convert_to_valueset: bool=False,
                           target_region: Optional[str]=None):
        """
        Translate an address into a series of internal representation of addresses that can be used to address in
        individual regions..

        :param addr:
        :param is_write:
        :param convert_to_valueset:
        :param target_region:
        :return:
        """

        targets_limit = WRITE_TARGETS_LIMIT if is_write else READ_TARGETS_LIMIT

        if type(addr) is not int:
            for constraint in self.state.solver.constraints:
                if getattr(addr, 'variables', set()) & constraint.variables:
                    addr = self._apply_condition_to_symbolic_addr(addr, constraint)

        # Apply the condition if necessary
        if condition is not None:
            addr = self._apply_condition_to_symbolic_addr(addr, condition)

        if type(addr) is int:
            addr = self.state.solver.BVV(addr, self.state.arch.bits)

        addr_with_regions = self._normalize_address_type(addr)
        address_wrappers = []

        for region, addr_si in addr_with_regions:
            concrete_addrs = addr_si.eval(targets_limit)

            if len(concrete_addrs) == targets_limit and HYBRID_SOLVER in self.state.options:
                exact = True if APPROXIMATE_FIRST not in self.state.options else None
                solutions = self.state.solver.eval_upto(addr, targets_limit, exact=exact)

                if len(solutions) < len(concrete_addrs):
                    concrete_addrs = [addr_si.intersection(s).eval(1)[0] for s in solutions]

            if len(concrete_addrs) == targets_limit:
                self.state.history.add_event('mem', message='concretized too many targets. address = %s' % addr_si)

            for c in concrete_addrs:
                aw = self._normalize_address(region, c, target_region=target_region)
                address_wrappers.append(aw)

        if convert_to_valueset:
            return [i.to_valueset(self.state) for i in address_wrappers]

        else:
            return address_wrappers
