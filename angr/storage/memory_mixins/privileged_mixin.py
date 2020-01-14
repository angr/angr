from .paged_memory_mixin import PagedMemoryMixin

class PrivilegedPagingMixin(PagedMemoryMixin):
    def _get_page(self, pageno: int, writing: bool, priv: bool=False, **kwargs):
        page = super()._get_page(pageno, writing)
        if not priv and o.STRICT_PAGE_ACCESS in self.state.options:
            if writing and not page.perm_write:
                raise SimSegfaultException(pageno * self.page_size, 'non-writable')
            if not writing and not page.perm_read:
                raise SimSegfaultException(pageno * self.page_size, 'non-readable')

        return page

    def _initialize_page(self, pageno: int, priv: bool=False, **kwargs):
        if not priv and o.STRICT_PAGE_ACCESS in self.state.options:
            raise SimSegfaultException(pageno * self.page_size, 'unmapped')

        return super()._initialize_page(pageno, **kwargs)

from ...errors import SimSegfaultException
from ... import sim_options as o
