import logging
from itertools import count
from typing import Dict, Optional, Generator, Union, List, TYPE_CHECKING

import claripy
from claripy.ast import Bool, Bits, BV
from claripy.vsa import ValueSet, RegionAnnotation

from ....sim_options import (HYBRID_SOLVER, APPROXIMATE_FIRST, AVOID_MULTIVALUED_READS, CONSERVATIVE_READ_STRATEGY,
    KEEP_MEMORY_READS_DISCRETE, CONSERVATIVE_WRITE_STRATEGY)
from ....state_plugins.sim_action_object import _raw_ast
from ....errors import SimMemoryError, SimAbstractMemoryError
from ...memory import AddressWrapper, RegionMap
from ..paged_memory.paged_memory_mixin import PagedMemoryMixin
from .region import MemoryRegion

if TYPE_CHECKING:
    from ....sim_state import SimState


_l = logging.getLogger(name=__name__)

invalid_read_ctr = count()


class RegionedMemoryMixin(PagedMemoryMixin):
    """
    Regioned memory.
    It maps memory addresses into different pages.
    """

    def __init__(self, write_targets_limit: int=2048, read_targets_limit: int=4096,
                 stack_region_map: Optional[RegionMap]=None,
                 generic_region_map: Optional[RegionMap]=None,
                 stack_size: int=65536,
                 cle_memory_backer: Optional=None,
                 dict_memory_backer: Optional[Dict]=None,
                 **kwargs):
        super().__init__(**kwargs)
        self._regions: Dict[MemoryRegion] = { }

        self._cle_memory_backer = cle_memory_backer
        self._dict_memory_backer = dict_memory_backer
        self._stack_size = stack_size
        self._stack_region_map = stack_region_map if stack_region_map is not None else RegionMap(True)
        self._generic_region_map = generic_region_map if generic_region_map is not None else RegionMap(False)

        self._write_targets_limit = write_targets_limit
        self._read_targets_limit = read_targets_limit

    def load(self, addr, size: Optional[Union[BV,int]]=None, endness=None, condition: Optional[Bool]=None, **kwargs):

        if isinstance(size, BV) and isinstance(size._model_vsa, ValueSet):
            _l.critical('load(): size %s is a ValueSet. Something is wrong.', size)
            if self.state.scratch.ins_addr is not None:
                var_name = 'invalid_read_%d_%#x' % (
                    next(invalid_read_ctr),
                    self.state.scratch.ins_addr
                )
            else:
                var_name = 'invalid_read_%d_None' % next(invalid_read_ctr)

            return self.state.solver.Unconstrained(var_name, self.state.arch.bits)

        val = None
        # TODO: Bad code. refactor it so that we don't end up enumerating all address wrappers
        regioned_addrs: List[AddressWrapper] = list(self._normalize_address(addr, is_write=False, condition=condition))

        if (len(regioned_addrs) > 1 and AVOID_MULTIVALUED_READS in self.state.options) or \
                (len(regioned_addrs) >= self._read_targets_limit and CONSERVATIVE_READ_STRATEGY in self.state.options):
            val = self.state.solver.Unconstrained('unconstrained_read', size * self.state.arch.byte_width)
            return val

        for aw in regioned_addrs:
            new_val = self._region_load(aw.address, size, aw.region,
                                        related_function_addr=aw.function_address,
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
            val = self.state.solver.Unconstrained('invalid_read_%d_%d' % (next(invalid_read_ctr), size),
                                                  size * self.state.arch.byte_width)

        return val

    def store(self, addr, data, size: Optional[int]=None, endness=None, **kwargs):
        regioned_addrs: List[AddressWrapper] = list(self._normalize_address(addr, is_write=True,
                                                                            convert_to_valueset=False))
        if len(regioned_addrs) >= self._write_targets_limit and CONSERVATIVE_WRITE_STRATEGY in self.state.options:
            return

        for a in regioned_addrs:
            self._region_store(a.address, data, a.region, endness,
                               related_function_addr=a.function_address)

    #
    # Region management
    #

    def _create_region(self, key: str, state: 'SimState', related_function_addr: int, endness,
                       cle_memory_backer: Optional=None, dict_memory_backer: Optional[Dict]=None):
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
        self._regions[key] = MemoryRegion(key,
                                          state=state,
                                          related_function_addr=related_function_addr,
                                          endness=endness,
                                          cle_memory_backer=cle_memory_backer,
                                          dict_memory_backer=dict_memory_backer,
                                          )

    def _region_base(self, region: str) -> int:
        """
        Get the base address of a memory region.

        :param region:  ID of the memory region
        :return:        Address of the memory region
        """

        if region == 'global':
            base_addr = 0
        elif region.startswith('stack_'):
            base_addr = self._stack_region_map.absolutize(region, 0)
        else:
            base_addr = self._generic_region_map.absolutize(region, 0)

        return base_addr

    def _region_load(self, addr, size, key: str, related_function_addr=None):
        bbl_addr, stmt_id, ins_addr = self.state.scratch.bbl_addr, self.state.scratch.stmt_idx, self.state.scratch.ins_addr

        if key not in self._regions:
            self._create_region(key, self.state, related_function_addr, self.endness,
                                cle_memory_backer=self._cle_memory_backer.get(key, None) if self._cle_memory_backer is not None else None,
                                dict_memory_backer=self._dict_memory_backer.get(key, None) if self._dict_memory_backer is not None else None,
                                )

        return self._regions[key].load(addr, size, bbl_addr, stmt_id, ins_addr)

    def _region_store(self, addr, data, key: str, endness, related_function_addr: Optional[int]=None):
        if key not in self._regions:
            self._create_region(key, self.state, related_function_addr, self.endness,
                                cle_memory_backer=self._cle_memory_backer.get(key, None) if self._cle_memory_backer is not None else None,
                                dict_memory_backer=self._dict_memory_backer.get(key, None) if self._dict_memory_backer is not None else None,
                                )

        self._regions[key].store(addr, data,
                                 self.state.scratch.bbl_addr,
                                 self.state.scratch.stmt_idx,
                                 self.state.scratch.ins_addr,
                                 endness=endness)

    #
    # Address conversion
    #

    def _normalize_address(self, addr: claripy.ast.Base, is_write: bool=False, convert_to_valueset: bool=False,
                           target_region: Optional[str]=None, condition=None) -> Generator[Bits,None,None]:
        """
        Translate an address into a series of internal representation of addresses that can be used to address in
        individual regions.

        :param addr:
        :param is_write:
        :param convert_to_valueset:
        :param target_region:
        :return:
        """

        targets_limit = self._write_targets_limit if is_write else self._read_targets_limit

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

        # TODO: Refactor this method so that it returns an AbstractAddressDescriptor that
        # TODO: - delays the creation of AddressWrapper
        # TODO: - allows getting the total number of addresses
        # TODO: this way we will not have to create all AddressWrapper objects in callers if there are too many addresses

        for region, addr_si in addr_with_regions:
            concrete_addrs = addr_si.eval(targets_limit)

            if len(concrete_addrs) == targets_limit and HYBRID_SOLVER in self.state.options:
                exact = True if APPROXIMATE_FIRST not in self.state.options else None
                solutions = self.state.solver.eval_upto(addr, targets_limit, exact=exact)

                if len(solutions) < len(concrete_addrs):
                    concrete_addrs = [addr_si.intersection(s).eval(1)[0] for s in solutions]

            for c in concrete_addrs:
                aw = self._normalize_address_core(region, c, target_region=target_region)
                if convert_to_valueset:
                    yield aw.to_valueset(self.state)
                else:
                    yield aw

    def _normalize_address_core(self, region_id: str, relative_address: int,
                                target_region: Optional[str]=None) -> AddressWrapper:
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
        if region_id.startswith('stack_'):
            absolute_address = self._stack_region_map.absolutize(region_id, relative_address)

        else:
            absolute_address = self._generic_region_map.absolutize(region_id, relative_address)

        stack_base = self._stack_region_map.stack_base

        if stack_base - self._stack_size < relative_address <= stack_base and \
                (target_region is not None and target_region.startswith('stack_')):
            # The absolute address seems to be in the stack region.
            # Map it to stack
            new_region_id, new_relative_address, related_function_addr = self._stack_region_map.relativize(
                absolute_address,
                target_region_id=target_region
            )

            return AddressWrapper(new_region_id, self._region_base(new_region_id), new_relative_address, True,
                                  related_function_addr
                                  )

        else:
            new_region_id, new_relative_address, related_function_addr = self._generic_region_map.relativize(
                absolute_address,
                target_region_id=target_region
            )

            return AddressWrapper(new_region_id, self._region_base(new_region_id), new_relative_address, False, None)

    def _apply_condition_to_symbolic_addr(self, addr, condition):
        _, converted = self.state.solver.constraint_to_si(condition)
        for original_expr, constrained_expr in converted:
            addr = addr.replace(original_expr, constrained_expr)
        return addr

    @staticmethod
    def _normalize_address_type(addr):
        """
        Convert address of different types to a list of mapping between region IDs and offsets (strided intervals).

        :param claripy.ast.Base addr: Address to convert
        :return: A list of mapping between region IDs and offsets.
        :rtype: dict
        """

        addr_e = _raw_ast(addr)

        if isinstance(addr_e, (claripy.bv.BVV, claripy.vsa.StridedInterval, claripy.vsa.ValueSet)):
            raise SimMemoryError('_normalize_address_type() does not take claripy models.')

        if isinstance(addr_e, claripy.ast.Base):
            if not isinstance(addr_e._model_vsa, ValueSet):
                # Convert it to a ValueSet first by annotating it
                addr_e = addr_e.annotate(RegionAnnotation('global', 0, addr_e._model_vsa))

            return addr_e._model_vsa.items()

        else:
            raise SimAbstractMemoryError('Unsupported address type %s' % type(addr_e))
