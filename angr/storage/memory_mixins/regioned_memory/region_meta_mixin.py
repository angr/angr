import copy
from typing import Dict, Tuple, Any

from claripy.vsa import AbstractLocation

from .. import MemoryMixin


class MemoryRegionMetaMixin(MemoryMixin):
    __slots__ = (
        "_endness",
        "_id",
        "_state",
        "_is_stack",
        "_related_function_addr",
        "_alocs",
        "_memory",
    )

    def __init__(self, related_function_addr=None, **kwargs):
        super().__init__(**kwargs)
        self._related_function_addr = related_function_addr
        # This is a map from tuple (basicblock_key, stmt_id) to AbstractLocation objects
        self.alocs: Dict[Tuple[Any, int], AbstractLocation] = {}

        self._is_stack = None

    @MemoryMixin.memo
    def copy(self, memo):
        r: "MemoryRegionMetaMixin" = super().copy(memo)
        r.alocs = copy.deepcopy(self.alocs)
        r._related_function_addr = self._related_function_addr
        r._is_stack = self._is_stack
        return r

    @property
    def is_stack(self):
        if self.id is None:
            return None
        if self._is_stack is None:
            self._is_stack = self.id.startswith("stack_")
        return self._is_stack

    @property
    def related_function_addr(self):
        return self._related_function_addr

    def get_abstract_locations(self, addr, size):
        """
        Get a list of abstract locations that is within the range of [addr, addr + size]

        This implementation is pretty slow. But since this method won't be called frequently, we can live with the bad
        implementation for now.

        :param addr:    Starting address of the memory region.
        :param size:    Size of the memory region, in bytes.
        :return:        A list of covered AbstractLocation objects, or an empty list if there is none.
        """

        ret = []
        for aloc in self.alocs.values():
            for seg in aloc.segments:
                if seg.offset >= addr and seg.offset < addr + size:
                    ret.append(aloc)
                    break

        return ret

    def store(self, addr, data, bbl_addr=None, stmt_id=None, ins_addr=None, endness=None, **kwargs):
        if ins_addr is not None:
            aloc_id = ins_addr
        else:
            # It comes from a SimProcedure. We'll use bbl_addr as the aloc_id
            aloc_id = bbl_addr

        if aloc_id not in self.alocs:
            self.alocs[aloc_id] = self.state.solver.AbstractLocation(
                bbl_addr, stmt_id, self.id, region_offset=addr, size=len(data) // self.state.arch.byte_width
            )
            return super().store(addr, data, endness=endness, **kwargs)
        else:
            if self.alocs[aloc_id].update(addr, len(data) // self.state.arch.byte_width):
                return super().store(addr, data, endness=endness, **kwargs)
            else:
                return super().store(addr, data, endness=endness, **kwargs)

    def load(
        self, addr, size=None, bbl_addr=None, stmt_idx=None, ins_addr=None, **kwargs
    ):  # pylint:disable=unused-argument
        # if bbl_addr is not None and stmt_id is not None:
        return super().load(addr, size=size, **kwargs)

    def _merge_alocs(self, other_region):
        """
        Helper function for merging.
        """
        merging_occurred = False
        for aloc_id, aloc in other_region.alocs.items():
            if aloc_id not in self.alocs:
                self.alocs[aloc_id] = aloc.copy()
                merging_occurred = True
            else:
                # Update it
                merging_occurred |= self.alocs[aloc_id].merge(aloc)
        return merging_occurred

    def merge(self, others, merge_conditions, common_ancestor=None) -> bool:
        r = False
        for other_region in others:
            self._merge_alocs(other_region)
            r |= super().merge([other_region], merge_conditions, common_ancestor=common_ancestor)
        return r

    def widen(self, others):
        for other_region in others:
            self._merge_alocs(other_region)
            super().widen([other_region.memory])

    def dbg_print(self, indent=0):
        """
        Print out debugging information
        """
        print("%sA-locs:" % (" " * indent))
        for aloc_id, aloc in self.alocs.items():
            print("{}<0x{:x}> {}".format(" " * (indent + 2), aloc_id, aloc))
