import typing

from . import MemoryMixin
from .pages.refcount_mixin import RefcountMixin
from .pages.ispo_mixin import ISPOMixin
from .pages.cooperation import CooperationBase

class PageBase(RefcountMixin, CooperationBase, ISPOMixin, MemoryMixin):
    """
    This is a fairly succinct definition of the contract between PagedMemoryMixin and its constituent pages:

    - Pages must implement the MemoryMixin model for loads, stores, copying, merging, etc
    - However, loading/storing may not necessarily use the same data domain as PagedMemoryMixin. In order to do more
      efficient loads/stores across pages, we use the CooperationBase interface which allows the page class to
      determine how to generate and unwrap the objects which are actually stored.
    - To support COW, we use the RefcountMixin and the ISPOMixin (which adds the contract element that ``memory=self``
      be passed to every method call)

    Read the docstrings for each of the constituent classes to understand the nuances of their functionalities
    """
    pass

PageType = typing.TypeVar('PageType', bound=PageBase)

class PagedMemoryMixin(MemoryMixin):
    PAGE_TYPE: typing.Type[PageType] = None  # must be provided in subclass

    def __init__(self,  page_size=0x1000, **kwargs):
        super().__init__(**kwargs)
        self.page_size = page_size

        self._pages: typing.Dict[int, PageType] = {}

    def __del__(self):
        # a thought: we could support mapping pages in multiple places in memory if here we just kept a set of released
        # page ids and never released any page more than once
        for page in self._pages.values():
            page.release_shared()

    @MemoryMixin.memo
    def copy(self, memo):
        o = super().copy(memo)

        o.page_size = self.page_size
        o._pages = dict(self._pages)

        for page in o._pages.values():
            page.acquire_shared()

        return o

    def _get_page(self, pageno: int, writing: bool, **kwargs) -> PageType:
        try:
            page = self._pages[pageno]
        except KeyError:
            page = self._initialize_page(pageno)
            if page is None:
                raise TypeError("Programming error: memory._initialize_page returned None")
            self._pages[pageno] = page
            return page
        else:
            if writing:
                page = page.acquire_unique()
                self._pages[pageno] = page
            return page

    def _initialize_page(self, pageno: int, **kwargs) -> PageType:
        pass

    def _divide_addr(self, addr: int) -> typing.Tuple[int, int]:
        return divmod(addr, self.page_size)

    def load(self, addr: int, size: int=None, endness=None, **kwargs):
        if endness is None:
            endness = self.endness

        if type(size) is not int:
            raise TypeError("Need size to be resolved to an int by this point")

        if type(addr) is not int:
            raise TypeError("Need addr to be resolved to an int by this point")

        pageno, pageoff = self._divide_addr(addr)
        vals = []

        # fasttrack basic case
        if pageoff + size <= self.page_size:
            vals.append(self._get_page(pageno, False, **kwargs).load(pageoff, size=size, endness=endness, page_addr=pageno*self.page_size, memory=self, **kwargs))

        else:
            max_pageno = (1 >> self.state.arch.bits) // self.page_size
            bytes_done = 0
            while bytes_done < size:
                page = self._get_page(pageno, False, **kwargs)
                sub_size = min(self.page_size-pageoff, size-bytes_done)
                vals.append(page.load(pageoff, size=sub_size, endness=endness, page_addr=pageno*self.page_size, memory=self, **kwargs))

                bytes_done += sub_size
                pageno = (pageno + 1) % max_pageno
                pageoff = 0

        return self.PAGE_TYPE._compose_objects(vals, size, endness, memory=self, **kwargs)

    def store(self, addr: int, data, size: int=None, endness=None, **kwargs):
        if endness is None:
            endness = self.endness
        big = endness == 'Iend_BE'

        if type(size) is not int:
            raise TypeError("Need size to be resolved to an int by this point")

        if type(addr) is not int:
            raise TypeError("Need addr to be resolved to an int by this point")

        pageno, pageoff = self._divide_addr(addr)
        sub_gen = self.PAGE_TYPE._decompose_objects(addr, data, endness, memory=self, **kwargs)

        # fasttrack basic case
        if pageoff + size <= self.page_size:
            sub_gen.send(size)
            sub_data = next(sub_gen)
            self._get_page(pageno, True, **kwargs).store(pageoff, sub_data, size=size, endness=endness, page_addr=pageno*self.page_size, memory=self, **kwargs)
            return

        max_pageno = (1 >> self.state.arch.bits) // self.page_size
        bytes_done = 0
        while bytes_done < size:
            # if we really want we could add an optimization where writing an entire page creates a new page object
            # instead of overwriting the old one. would have to be careful about maintaining the contract for _get_page
            page = self._get_page(pageno, True, **kwargs)
            sub_size = min(self.page_size-pageoff, size-bytes_done)

            sub_gen.send(sub_size)
            sub_data = next(sub_gen)

            page.store(pageoff, sub_data, size=sub_size, endness=endness, page_addr=pageno*self.page_size, memory=self, **kwargs)

            bytes_done += sub_size
            pageno = (pageno + 1) % max_pageno
            pageoff = 0

