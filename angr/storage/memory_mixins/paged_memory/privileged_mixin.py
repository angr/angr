from __future__ import annotations
from .paged_memory_mixin import PagedMemoryMixin


class PrivilegedPagingMixin(PagedMemoryMixin):
    """
    A mixin for paged memory models which will raise SimSegfaultExceptions if STRICT_PAGE_ACCESS is enabled and
    a segfault condition is detected.

    Segfault conditions include:
    - getting a page for reading which is non-readable
    - getting a page for writing which is non-writable
    - creating a page

    The latter condition means that this should be inserted under any mixins which provide other implementations of
    ``_initialize_page``.
    """

    def _get_page(self, pageno: int, writing: bool, priv: bool = False, **kwargs):
        page = super()._get_page(pageno, writing, **kwargs)
        if self.category == "mem" and not priv and o.STRICT_PAGE_ACCESS in self.state.options:
            if writing and not self.state.solver.is_true(page.perm_write):
                raise SimSegfaultException(pageno * self.page_size, "non-writable")
            if not writing and not self.state.solver.is_true(page.perm_read):
                raise SimSegfaultException(pageno * self.page_size, "non-readable")

        return page

    def _initialize_page(self, pageno: int, priv: bool = False, **kwargs):
        if self.category == "mem" and not priv and o.STRICT_PAGE_ACCESS in self.state.options:
            raise SimSegfaultException(pageno * self.page_size, "unmapped")

        return super()._initialize_page(pageno, **kwargs)


from angr.errors import SimSegfaultException
from angr import sim_options as o
