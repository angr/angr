from angr.storage.memory_mixins.base import MemoryMixin


class RegionCategoryMixin(MemoryMixin):
    @property
    def category(self):
        return "mem"
