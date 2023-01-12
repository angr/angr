import logging

from typing import Union, List

from ...knowledge_plugins.key_definitions.heap_address import HeapAddress
from ...knowledge_plugins.key_definitions.unknown_size import UnknownSize
from ...knowledge_plugins.key_definitions.undefined import Undefined

_l = logging.getLogger(name=__name__)


class HeapAllocator:
    """
    A simple modelisation to help represent heap memory management during a <ReachingDefinitionsAnalysis>:
    - Act as if allocations were always done in consecutive memory segments;
    - Take care of the size not to screw potential pointer arithmetic (avoid overlapping segments).

    The content of the heap itself is modeled using a <KeyedRegion> attribute in the <LiveDefinitions> state;
    This class serves to generate consistent heap addresses to be used by the aforementionned.

    *Note:* This has **NOT** been made to help detect heap vulnerabilities.
    """

    def __init__(self, canonical_size: int):
        """
        :param canonical_size: The concrete size an <UNKNOWN_SIZE> defaults to.
        """
        self._next_heap_address: HeapAddress = HeapAddress(0)
        self._allocated_addresses: List[HeapAddress] = [self._next_heap_address]
        self._canonical_size: int = canonical_size

    def allocate(self, size: Union[int, UnknownSize]) -> HeapAddress:
        """
        Gives an address for a new memory chunck of <size> bytes.

        :param size: The requested size for the chunck, in number of bytes.
        :return: The address of the chunck.
        """
        address = self._next_heap_address

        size = self._canonical_size if isinstance(size, UnknownSize) else size
        self._next_heap_address += size

        self._allocated_addresses += [self._next_heap_address]

        return address

    def free(self, address: Union[Undefined, HeapAddress]):
        """
        Mark the chunck pointed by <address> as freed.

        :param address: The address of the chunck to free.
        """

        if isinstance(address, Undefined):
            _l.debug("free(), Undefined address provided")
        elif isinstance(address, HeapAddress):
            try:
                self._allocated_addresses.remove(address)
            except ValueError:
                _l.warning("free(), address %s had not been allocated", address)
        else:
            _l.warning("free(), expected HeapAddress, or Undefined, got %s", type(address).__name__)

    @property
    def allocated_addresses(self):
        """
        :return: The list of addresses that are currently allocated on the heap.
        """
        return self._allocated_addresses
