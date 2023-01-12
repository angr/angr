from typing import Optional
from sortedcontainers import SortedDict

from ....errors import SimRegionMapError
from ....state_plugins import SimStatePlugin


class AddressWrapper:
    """
    AddressWrapper is used in SimAbstractMemory, which provides extra meta information for an address (or a ValueSet
    object) that is normalized from an integer/BVV/StridedInterval.
    """

    __slots__ = (
        "region",
        "region_base_addr",
        "address",
        "is_on_stack",
        "function_address",
    )

    def __init__(self, region: str, region_base_addr: int, address, is_on_stack: bool, function_address: Optional[int]):
        """
        Constructor for the class AddressWrapper.

        :param region:              Name of the memory regions it belongs to.
        :param region_base_addr:    Base address of the memory region
        :param address:             An address (not a ValueSet object).
        :param is_on_stack:         Whether this address is on a stack region or not.
        :param function_address:    Related function address (if any).
        """
        self.region = region
        self.region_base_addr = region_base_addr
        self.address = address
        self.is_on_stack = is_on_stack
        self.function_address = function_address

    def __hash__(self):
        return hash((self.region, self.address))

    def __eq__(self, other):
        return self.region == other.region and self.address == other.address

    def __repr__(self):
        return f"<{self.region}> {hex(self.address)}"

    def to_valueset(self, state):
        """
        Convert to a ValueSet instance

        :param state: A state
        :return: The converted ValueSet instance
        """
        return state.solver.VS(state.arch.bits, self.region, self.region_base_addr, self.address)


class RegionDescriptor:
    """
    Descriptor for a memory region ID.
    """

    __slots__ = (
        "region_id",
        "base_address",
        "related_function_address",
    )

    def __init__(self, region_id, base_address, related_function_address=None):
        self.region_id = region_id
        self.base_address = base_address
        self.related_function_address = related_function_address

    def __repr__(self):
        return "<{} - {:#x}>".format(
            self.region_id, self.related_function_address if self.related_function_address is not None else 0
        )


class RegionMap:
    """
    Mostly used in SimAbstractMemory, RegionMap stores a series of mappings between concrete memory address ranges and
    memory regions, like stack frames and heap regions.
    """

    def __init__(self, is_stack):
        """
        Constructor

        :param is_stack:    Whether this is a region map for stack frames or not. Different strategies apply for stack
                            regions.
        """
        self.is_stack = is_stack

        # A sorted list, which maps stack addresses to region IDs
        self._address_to_region_id = SortedDict()
        # A dict, which maps region IDs to memory address ranges
        self._region_id_to_address = {}

    #
    # Properties
    #

    def __repr__(self):
        return "RegionMap<%s>" % ("S" if self.is_stack else "H")

    @property
    def is_empty(self):
        return len(self._address_to_region_id) == 0

    @property
    def stack_base(self):
        if not self.is_stack:
            raise SimRegionMapError('Calling "stack_base" on a non-stack region map.')

        return next(self._address_to_region_id.irange(reverse=True))

    @property
    def region_ids(self):
        return self._region_id_to_address.keys()

    #
    # Public methods
    #

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        r = RegionMap(is_stack=self.is_stack)

        # A shallow copy should be enough, since we never modify any RegionDescriptor object in-place
        r._address_to_region_id = self._address_to_region_id.copy()
        r._region_id_to_address = self._region_id_to_address.copy()

        return r

    def map(self, absolute_address, region_id, related_function_address=None):
        """
        Add a mapping between an absolute address and a region ID. If this is a stack region map, all stack regions
        beyond (lower than) this newly added regions will be discarded.

        :param absolute_address:            An absolute memory address.
        :param region_id:                   ID of the memory region.
        :param related_function_address:    A related function address, mostly used for stack regions.
        """

        if self.is_stack:
            # Sanity check
            if not region_id.startswith("stack_"):
                raise SimRegionMapError('Received a non-stack memory ID "%d" in a stack region map' % region_id)

            # Remove all stack regions that are lower than the one to add
            while True:
                try:
                    addr = next(self._address_to_region_id.irange(maximum=absolute_address, reverse=True))
                    descriptor = self._address_to_region_id[addr]
                    # Remove this mapping
                    del self._address_to_region_id[addr]
                    # Remove this region ID from the other mapping
                    del self._region_id_to_address[descriptor.region_id]
                except StopIteration:
                    break

        else:
            if absolute_address in self._address_to_region_id:
                descriptor = self._address_to_region_id[absolute_address]
                # Remove this mapping
                del self._address_to_region_id[absolute_address]
                del self._region_id_to_address[descriptor.region_id]

        # Add this new region mapping
        desc = RegionDescriptor(region_id, absolute_address, related_function_address=related_function_address)

        self._address_to_region_id[absolute_address] = desc
        self._region_id_to_address[region_id] = desc

    def unmap_by_address(self, absolute_address):
        """
        Removes a mapping based on its absolute address.

        :param absolute_address: An absolute address
        """

        desc = self._address_to_region_id[absolute_address]
        del self._address_to_region_id[absolute_address]
        del self._region_id_to_address[desc.region_id]

    def absolutize(self, region_id, relative_address):
        """
        Convert a relative address in some memory region to an absolute address.

        :param region_id:           The memory region ID
        :param relative_address:    The relative memory offset in that memory region
        :return:                    An absolute address if converted, or an exception is raised when region id does not
                                    exist.
        """

        if region_id == "global":
            # The global region always bases 0
            return relative_address

        if region_id not in self._region_id_to_address:
            raise SimRegionMapError('Non-existent region ID "%s"' % region_id)

        base_address = self._region_id_to_address[region_id].base_address
        return base_address + relative_address

    def relativize(self, absolute_address, target_region_id=None):
        """
        Convert an absolute address to the memory offset in a memory region.

        Note that if an address belongs to heap region is passed in to a stack region map, it will be converted to an
        offset included in the closest stack frame, and vice versa for passing a stack address to a heap region.
        Therefore you should only pass in address that belongs to the same category (stack or non-stack) of this region
        map.

        :param absolute_address:    An absolute memory address
        :return:                    A tuple of the closest region ID, the relative offset, and the related function
                                    address.
        """

        if target_region_id is None:
            if self.is_stack:
                # Get the base address of the stack frame it belongs to
                base_address = next(self._address_to_region_id.irange(minimum=absolute_address, reverse=False))

            else:
                try:
                    base_address = next(self._address_to_region_id.irange(maximum=absolute_address, reverse=True))

                except StopIteration:
                    # Not found. It belongs to the global region then.
                    return "global", absolute_address, None

            descriptor = self._address_to_region_id[base_address]

        else:
            if target_region_id == "global":
                # Just return the absolute address
                return "global", absolute_address, None

            if target_region_id not in self._region_id_to_address:
                raise SimRegionMapError('Trying to relativize to a non-existent region "%s"' % target_region_id)

            descriptor = self._region_id_to_address[target_region_id]
            base_address = descriptor.base_address

        return descriptor.region_id, absolute_address - base_address, descriptor.related_function_address
