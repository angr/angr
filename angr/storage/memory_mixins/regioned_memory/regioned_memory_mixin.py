import logging
from itertools import count
from typing import Dict, Optional, Generator, Union, TYPE_CHECKING, Tuple, Iterable

import claripy
from claripy.ast import Bool, Bits, BV
from claripy.vsa import StridedInterval, ValueSet, RegionAnnotation

from ....sim_options import (
    AVOID_MULTIVALUED_READS,
    CONSERVATIVE_READ_STRATEGY,
    KEEP_MEMORY_READS_DISCRETE,
    CONSERVATIVE_WRITE_STRATEGY,
)
from ....state_plugins.sim_action_object import _raw_ast
from ....errors import SimMemoryError, SimAbstractMemoryError
from .. import MemoryMixin
from .region_data import AddressWrapper, RegionMap
from .abstract_address_descriptor import AbstractAddressDescriptor

if TYPE_CHECKING:
    from ....sim_state import SimState


_l = logging.getLogger(name=__name__)

invalid_read_ctr = count()


class RegionedMemoryMixin(MemoryMixin):
    """
    Regioned memory. This mixin manages multiple memory regions. Each address is represented as a tuple of (region ID,
    offset into the region), which is called a regioned address.

    Converting absolute addresses into regioned addresses: We map an absolute address to a region by looking up which
    region this address belongs to in the region map. Currently this is only enabled for stack. Heap support has not
    landed yet.

    When start analyzing a function, the user should call set_stack_address_mapping() to create a new region mapping.
    Likewise, when exiting from a function, the user should cancel the previous mapping by calling
    unset_stack_address_mapping().
    """

    def __init__(
        self,
        write_targets_limit: int = 2048,
        read_targets_limit: int = 4096,
        stack_region_map: Optional[RegionMap] = None,
        generic_region_map: Optional[RegionMap] = None,
        stack_size: int = 65536,
        cle_memory_backer: Optional = None,
        dict_memory_backer: Optional[Dict] = None,
        regioned_memory_cls: Optional[type] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)

        if regioned_memory_cls is None:
            # delayed import
            from .. import RegionedMemory

            regioned_memory_cls = RegionedMemory

        self._regioned_memory_cls = regioned_memory_cls
        self._regions: Dict[str, regioned_memory_cls] = {}

        self._cle_memory_backer = cle_memory_backer
        self._dict_memory_backer = dict_memory_backer
        self._stack_size: int = stack_size
        self._stack_region_map: Optional[RegionMap] = (
            stack_region_map if stack_region_map is not None else RegionMap(True)
        )
        self._generic_region_map: Optional[RegionMap] = (
            generic_region_map if generic_region_map is not None else RegionMap(False)
        )

        self._write_targets_limit = write_targets_limit
        self._read_targets_limit = read_targets_limit

    @MemoryMixin.memo
    def copy(self, memo):
        o: "RegionedMemoryMixin" = super().copy(memo)
        o._write_targets_limit = self._write_targets_limit
        o._read_targets_limit = self._read_targets_limit
        o._stack_size = self._stack_size
        o._endness = self.endness
        o._stack_region_map = self._stack_region_map
        o._generic_region_map = self._generic_region_map
        o._cle_memory_backer = self._cle_memory_backer
        o._dict_memory_backer = self._dict_memory_backer
        o._regioned_memory_cls = self._regioned_memory_cls

        o._regions = {}
        for region_id, region in self._regions.items():
            o._regions[region_id] = region.copy(memo)

        return o

    def load(
        self, addr, size: Optional[Union[BV, int]] = None, endness=None, condition: Optional[Bool] = None, **kwargs
    ):
        if isinstance(size, BV) and isinstance(size._model_vsa, ValueSet):
            _l.critical("load(): size %s is a ValueSet. Something is wrong.", size)
            if self.state.scratch.ins_addr is not None:
                var_name = "invalid_read_%d_%#x" % (next(invalid_read_ctr), self.state.scratch.ins_addr)
            else:
                var_name = "invalid_read_%d_None" % next(invalid_read_ctr)

            return self.state.solver.Unconstrained(var_name, self.state.arch.bits)

        val = None
        regioned_addrs_desc = self._normalize_address(addr, condition=condition)

        if (regioned_addrs_desc.cardinality > 1 and AVOID_MULTIVALUED_READS in self.state.options) or (
            regioned_addrs_desc.cardinality >= self._read_targets_limit
            and CONSERVATIVE_READ_STRATEGY in self.state.options
        ):
            val = self.state.solver.Unconstrained("unconstrained_read", size * self.state.arch.byte_width)
            return val

        gen = self._concretize_address_descriptor(regioned_addrs_desc, addr, is_write=False)
        for aw in gen:
            new_val = self._region_load(
                aw.address,
                size,
                aw.region,
                endness=endness,
                related_function_addr=aw.function_address,
                **kwargs,
            )

            if val is None:
                if KEEP_MEMORY_READS_DISCRETE in self.state.options:
                    val = self.state.solver.DSIS(to_conv=new_val, max_card=100000)
                else:
                    val = new_val
            else:
                val = val.union(new_val)

        if val is None:
            # address_wrappers is empty - we cannot concretize the address in static mode.
            # ensure val is not None
            val = self.state.solver.Unconstrained(
                "invalid_read_%d_%d" % (next(invalid_read_ctr), size), size * self.state.arch.byte_width
            )

        return val

    def store(self, addr, data, size: Optional[int] = None, endness=None, **kwargs):
        regioned_addrs_desc = self._normalize_address(addr)
        if (
            regioned_addrs_desc.cardinality >= self._write_targets_limit
            and CONSERVATIVE_WRITE_STRATEGY in self.state.options
        ):
            return

        gen = self._concretize_address_descriptor(regioned_addrs_desc, addr, is_write=True)
        for aw in gen:
            self._region_store(aw.address, data, aw.region, endness, related_function_addr=aw.function_address)

    def merge(self, others: Iterable["RegionedMemoryMixin"], merge_conditions, common_ancestor=None) -> bool:
        r = False
        for o in others:
            for region_id, region in o._regions.items():
                if region_id in self._regions:
                    r |= self._regions[region_id].merge([region], merge_conditions, common_ancestor=common_ancestor)
                else:
                    self._regions[region_id] = region
                    r = True
        return r

    def find(self, addr: Union[int, Bits], data, max_search, **kwargs):
        # FIXME: Attempt find() on more than one region

        gen = self._normalize_address_type(addr, self.state.arch.bits)

        for region, si in gen:
            si = claripy.SI(to_conv=si)
            r, s, i = self._regions[region].find(si, data, max_search, **kwargs)
            # Post-process r so that it's still a ValueSet
            region_base_addr = self._region_base(region)
            r = self.state.solver.ValueSet(r.size(), region, region_base_addr, r._model_vsa)
            return r, s, i

    def set_state(self, state):
        for region in self._regions.values():
            region.set_state(state)
        super().set_state(state)

    def replace_all(self, old: claripy.ast.BV, new: claripy.ast.BV):
        for region in self._regions.values():
            region.replace_all(old, new)

    #
    # Region management
    #

    def set_stack_address_mapping(
        self, absolute_address: int, region_id: str, related_function_address: Optional[int] = None
    ):
        """
        Create a new mapping between an absolute address (which is the base address of a specific stack frame) and a
        region ID.

        :param absolute_address: The absolute memory address.
        :param region_id: The region ID.
        :param related_function_address: Related function address.
        """
        if self._stack_region_map is None:
            raise SimMemoryError("Stack region map is not initialized.")
        self._stack_region_map.map(absolute_address, region_id, related_function_address=related_function_address)

    def unset_stack_address_mapping(self, absolute_address: int):
        """
        Remove a stack mapping.

        :param absolute_address: An absolute memory address that is the base address of the stack frame to destroy.
        """
        if self._stack_region_map is None:
            raise SimMemoryError("Stack region map is not initialized.")
        self._stack_region_map.unmap_by_address(absolute_address)

    def stack_id(self, function_address: int) -> str:
        """
        Return a memory region ID for a function. If the default region ID exists in the region mapping, an integer
        will appended to the region name. In this way we can handle recursive function calls, or a function that
        appears more than once in the call frame.

        This also means that `stack_id()` should only be called when creating a new stack frame for a function. You are
        not supposed to call this function every time you want to map a function address to a stack ID.

        :param function_address: Address of the function.
        :return:                ID of the new memory region.
        """
        region_id = "stack_%#x" % function_address

        # deduplication
        region_ids = self._stack_region_map.region_ids
        if region_id not in region_ids:
            return region_id
        else:
            for i in range(0, 2000):
                new_region_id = region_id + "_%d" % i
                if new_region_id not in region_ids:
                    return new_region_id
            raise SimMemoryError("Cannot allocate region ID for function %#08x - recursion too deep" % function_address)

    def set_stack_size(self, size: int):
        self._stack_size = size

    def _create_region(
        self,
        key: str,
        state: "SimState",
        related_function_addr: int,
        endness,
        cle_memory_backer: Optional = None,
        dict_memory_backer: Optional[Dict] = None,
    ):
        """
        Create a new MemoryRegion with the region key specified, and store it to self._regions.

        :param key: a string which is the region key
        :param state: the SimState instance
        :param is_stack: Whether this memory region is on stack. True/False
        :param related_function_addr: Which function first creates this memory region. Just for reference.
        :param endness: The endianness.
        :param backer_dict: The memory backer object.
        :return: None
        """
        self._regions[key] = self._regioned_memory_cls(
            memory_id=key,
            related_function_addr=related_function_addr,
            endness=endness,
            cle_memory_backer=cle_memory_backer,
            dict_memory_backer=dict_memory_backer,
        )
        self._regions[key].set_state(state)

    def _region_base(self, region: str) -> int:
        """
        Get the base address of a memory region.

        :param region:  ID of the memory region
        :return:        Address of the memory region
        """

        if region == "global":
            base_addr = 0
        elif region.startswith("stack_"):
            base_addr = self._stack_region_map.absolutize(region, 0)
        else:
            base_addr = self._generic_region_map.absolutize(region, 0)

        return base_addr

    def _region_load(self, addr, size, key: str, related_function_addr=None, **kwargs):
        bbl_addr, stmt_id, ins_addr = (
            self.state.scratch.bbl_addr,
            self.state.scratch.stmt_idx,
            self.state.scratch.ins_addr,
        )

        if key not in self._regions:
            self._create_region(
                key,
                self.state,
                related_function_addr,
                self.endness,
                cle_memory_backer=self._cle_memory_backer.get(key, None)
                if self._cle_memory_backer is not None
                else None,
                dict_memory_backer=self._dict_memory_backer.get(key, None)
                if self._dict_memory_backer is not None
                else None,
            )

        return self._regions[key].load(addr, size, bbl_addr, stmt_id, ins_addr, **kwargs)

    def _region_store(self, addr, data, key: str, endness, related_function_addr: Optional[int] = None, **kwargs):
        if key not in self._regions:
            self._create_region(
                key,
                self.state,
                related_function_addr,
                self.endness,
                cle_memory_backer=self._cle_memory_backer.get(key, None)
                if self._cle_memory_backer is not None
                else None,
                dict_memory_backer=self._dict_memory_backer.get(key, None)
                if self._dict_memory_backer is not None
                else None,
            )

        self._regions[key].store(
            addr,
            data,
            self.state.scratch.bbl_addr,
            self.state.scratch.stmt_idx,
            self.state.scratch.ins_addr,
            endness=endness,
            **kwargs,
        )

    #
    # Address concretization and conversion
    #

    def _concretize_address_descriptor(
        self,
        desc: AbstractAddressDescriptor,
        original_addr: claripy.ast.Bits,
        is_write: bool = False,
        target_region: Optional[str] = None,
    ) -> Generator[AddressWrapper, None, None]:
        raise NotImplementedError()

    def _normalize_address(self, addr: claripy.ast.Bits, condition=None) -> AbstractAddressDescriptor:
        """
        Translate an address into a series of internal representation of addresses that can be used to address in
        individual regions.

        :param addr:
        :param is_write:
        :param convert_to_valueset:
        :param target_region:
        :return:
        """

        if type(addr) is not int:
            for constraint in self.state.solver.constraints:
                if getattr(addr, "variables", set()) & constraint.variables:
                    addr = self._apply_condition_to_symbolic_addr(addr, constraint)

        # Apply the condition if necessary
        if condition is not None:
            addr = self._apply_condition_to_symbolic_addr(addr, condition)

        addr_with_regions = self._normalize_address_type(addr, self.state.arch.bits)

        desc = AbstractAddressDescriptor()
        for region, addr_si in addr_with_regions:
            desc.add_regioned_address(region, addr_si)
        return desc

    def _normalize_address_core(
        self, region_id: str, relative_address: int, target_region: Optional[str] = None
    ) -> AddressWrapper:
        """
        If this is a stack address, we convert it to a correct region and address

        :param region_id: a string indicating which region the address is relative to
        :param relative_address: an address that is relative to the region parameter
        :param target_region: the ideal target region that address is normalized to. None means picking the best fit.
        :return: an AddressWrapper object
        """
        if self._stack_region_map.is_empty and self._generic_region_map.is_empty:
            # We don't have any mapped region right now
            return AddressWrapper(region_id, 0, relative_address, False, None)

        # We wanna convert this address to an absolute address first
        if region_id.startswith("stack_"):
            absolute_address = self._stack_region_map.absolutize(region_id, relative_address)

        else:
            absolute_address = self._generic_region_map.absolutize(region_id, relative_address)

        stack_base = self._stack_region_map.stack_base

        if stack_base - self._stack_size < relative_address <= stack_base and (
            target_region is not None and target_region.startswith("stack_")
        ):
            # The absolute address seems to be in the stack region.
            # Map it to stack
            new_region_id, new_relative_address, related_function_addr = self._stack_region_map.relativize(
                absolute_address, target_region_id=target_region
            )

            return AddressWrapper(
                new_region_id, self._region_base(new_region_id), new_relative_address, True, related_function_addr
            )

        else:
            new_region_id, new_relative_address, related_function_addr = self._generic_region_map.relativize(
                absolute_address, target_region_id=target_region
            )

            return AddressWrapper(new_region_id, self._region_base(new_region_id), new_relative_address, False, None)

    def _apply_condition_to_symbolic_addr(self, addr, condition):
        _, converted = self.state.solver.constraint_to_si(condition)
        for original_expr, constrained_expr in converted:
            addr = addr.replace(original_expr, constrained_expr)
        return addr

    @staticmethod
    def _normalize_address_type(addr: Union[int, Bits], bits) -> Generator[Tuple[str, StridedInterval], None, None]:
        """
        Convert address of different types to a list of mapping between region IDs and offsets (strided intervals).

        :param addr: Address to convert
        :return: A list of mapping between region IDs and offsets.
        :rtype: dict
        """

        if isinstance(addr, int):
            addr_e = claripy.BVV(addr, bits)
        else:
            addr_e = _raw_ast(addr)

        if isinstance(addr_e, (claripy.bv.BVV, claripy.vsa.StridedInterval, claripy.vsa.ValueSet)):
            raise SimMemoryError("_normalize_address_type() does not take claripy models.")

        if isinstance(addr_e, claripy.ast.Base):
            if not isinstance(addr_e._model_vsa, ValueSet):
                # Convert it to a ValueSet first by annotating it
                addr_e = addr_e.annotate(RegionAnnotation("global", 0, addr_e._model_vsa))

            model_vsa = addr_e._model_vsa
            if isinstance(model_vsa, ValueSet):
                yield from model_vsa.items()
            else:
                raise SimAbstractMemoryError("Cannot parse address as a VSA ValueSet")
        else:
            raise SimAbstractMemoryError("Unsupported address type %s" % type(addr_e))
