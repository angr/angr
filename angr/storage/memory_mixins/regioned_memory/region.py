from typing import Optional, TYPE_CHECKING
import copy

from .. import MemoryMixin

if TYPE_CHECKING:
    from .. import RegionMemory


class MemoryRegion:

    __slots__ = ('_endness', '_id', '_state', '_is_stack', '_related_function_addr', '_alocs', '_memory', )

    def __init__(self, mem_id, state, related_function_addr=None, init_memory=True, cle_memory_backer=None,
                 dict_memory_backer=None, endness=None):
        self._endness = endness
        self._id = mem_id
        self._state = state
        self._is_stack = mem_id.startswith('stack_') # TODO: Fix it
        self._related_function_addr = related_function_addr
        # This is a map from tuple (basicblock_key, stmt_id) to
        # AbstractLocation objects
        self._alocs = { }

        self._memory: Optional['RegionMemory'] = None

        if init_memory:
            # delayed import
            from .. import RegionMemory
            self._memory = RegionMemory(memory_id=mem_id, endness=self._endness,
                                        cle_memory_backer=cle_memory_backer, dict_memory_backer=dict_memory_backer,
                                        )

            self._memory.set_state(state)

    @property
    def id(self):
        return self._id

    @property
    def memory(self):
        return self._memory

    @property
    def state(self):
        return self._state

    @property
    def alocs(self):
        return self._alocs

    @property
    def is_stack(self):
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

        ret = [ ]
        for aloc in self._alocs.values():
            for seg in aloc.segments:
                if seg.offset >= addr and seg.offset < addr + size:
                    ret.append(aloc)
                    break

        return ret

    def addrs_for_name(self, name):
        return self.memory.addrs_for_name(name)

    def set_state(self, state):
        self._state = state
        self._memory.set_state(state)

    @MemoryMixin.memo
    def copy(self, memo):
        r = MemoryRegion(self._id, self.state,
                         related_function_addr=self._related_function_addr,
                         init_memory=False,
                         endness=self._endness,
                         )
        r._memory = self.memory.copy(memo)
        r._alocs = copy.deepcopy(self._alocs)
        return r

    def store(self, addr, data, bbl_addr, stmt_id, ins_addr, endness=None, **kwargs):
        if ins_addr is not None:
            aloc_id = ins_addr
        else:
            # It comes from a SimProcedure. We'll use bbl_addr as the aloc_id
            aloc_id = bbl_addr

        if aloc_id not in self._alocs:
            self._alocs[aloc_id] = self.state.solver.AbstractLocation(bbl_addr,
                                                                  stmt_id,
                                                                  self.id,
                                                                  region_offset=addr,
                                                                  size=len(data) // self.state.arch.byte_width)
            return self.memory.store(addr, data, **kwargs)
        else:
            if self._alocs[aloc_id].update(addr, len(data) // self.state.arch.byte_width):
                return self.memory.store(addr, data, endness=endness, **kwargs)
            else:
                return self.memory.store(addr, data, endness=endness, **kwargs)

    def load(self, addr, size, bbl_addr, stmt_idx, ins_addr, **kwargs): #pylint:disable=unused-argument
        #if bbl_addr is not None and stmt_id is not None:
        return self.memory.load(addr, size, **kwargs)

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

    def merge(self, others, merge_conditions, common_ancestor=None):
        for other_region in others:
            self._merge_alocs(other_region)
            self.memory.merge(
                [other_region.memory], merge_conditions, common_ancestor=common_ancestor
            )

    def widen(self, others):
        widening_occurred = False
        for other_region in others:
            widening_occurred |= self._merge_alocs(other_region)
            widening_occurred |= self.memory.widen([ other_region.memory ])
        return widening_occurred

    def __contains__(self, addr):
        return addr in self.memory

    def was_written_to(self, addr):
        return self.memory.was_written_to(addr)

    def dbg_print(self, indent=0):
        """
        Print out debugging information
        """
        print("%sA-locs:" % (" " * indent))
        for aloc_id, aloc in self._alocs.items():
            print("%s<0x%x> %s" % (" " * (indent + 2), aloc_id, aloc))

        print("%sMemory:" % (" " * indent))
        self.memory.dbg_print(indent=indent + 2)