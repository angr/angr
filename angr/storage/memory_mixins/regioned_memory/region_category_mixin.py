
from .. import MemoryMixin


class RegionCategoryMixin(MemoryMixin):
    @property
    def category(self):
        return 'mem'
