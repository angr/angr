
from typing import Dict

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

    def load(self, addr: int, size: int=None, endness=None, **kwargs):
        raise NotImplementedError()

    def store(self, addr: int, data, size: int=None, endness=None, **kwargs):
        raise NotImplementedError()
