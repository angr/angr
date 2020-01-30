import typing

from angr.storage.memory_mixins import MemoryMixin
from angr.storage.memory_mixins.paged_memory.pages import PageType, ListStorageMixin

class PagedMemoryMixin(MemoryMixin):
    PAGE_TYPE: typing.Type[PageType] = None  # must be provided in subclass

    def __init__(self,  page_size=0x1000, default_permissions=3, permissions_map=None, **kwargs):
        super().__init__(**kwargs)
        self.page_size = page_size

        self._permissions_map = permissions_map if permissions_map is not None else {}
        self._default_permissions = default_permissions
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
        o._permissions_map = self._permissions_map
        o._default_permissions = self._default_permissions

        for page in o._pages.values():
            page.acquire_shared()

        return o

    def _get_page(self, pageno: int, writing: bool, **kwargs) -> PageType:
        try:
            page = self._pages[pageno]
        except KeyError:
            page = self._initialize_page(pageno)
            self._pages[pageno] = page

        if writing:
            page = page.acquire_unique()
            self._pages[pageno] = page
        return page

    def _initialize_page(self, pageno: int, permissions=None, **kwargs) -> PageType:
        # permissions lookup: let permissions kwarg override everything else
        # then try the permissions map
        # then fall back to the default permissions
        if permissions is None:
            permissions = self._default_permissions
            addr = pageno * self.page_size

            for (start, end), perms in self._permissions_map.items():
                if start <= addr <= end:
                    permissions = perms
                    break

        return self.PAGE_TYPE(memory=self, memory_id='%s_%d' % (self.id, pageno), permissions=permissions)

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
            max_pageno = (1 << self.state.arch.bits) // self.page_size
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

        if type(size) is not int:
            raise TypeError("Need size to be resolved to an int by this point")

        if type(addr) is not int:
            raise TypeError("Need addr to be resolved to an int by this point")

        pageno, pageoff = self._divide_addr(addr)
        sub_gen = self.PAGE_TYPE._decompose_objects(addr, data, endness, memory=self, **kwargs)
        next(sub_gen)

        # fasttrack basic case
        if pageoff + size <= self.page_size:
            sub_data = sub_gen.send(size)
            self._get_page(pageno, True, **kwargs).store(pageoff, sub_data, size=size, endness=endness, page_addr=pageno*self.page_size, memory=self, **kwargs)
            sub_gen.close()
            return

        max_pageno = (1 << self.state.arch.bits) // self.page_size
        bytes_done = 0
        while bytes_done < size:
            # if we really want we could add an optimization where writing an entire page creates a new page object
            # instead of overwriting the old one. would have to be careful about maintaining the contract for _get_page
            page = self._get_page(pageno, True, **kwargs)
            sub_size = min(self.page_size-pageoff, size-bytes_done)

            sub_data = sub_gen.send(sub_size)

            page.store(pageoff, sub_data, size=sub_size, endness=endness, page_addr=pageno*self.page_size, memory=self, **kwargs)

            bytes_done += sub_size
            pageno = (pageno + 1) % max_pageno
            pageoff = 0

        sub_gen.close()

    def _simple_store(self, page, addr, data, size, endness, **kwargs):
        page_addr = addr - (addr % self.page_size)
        sub_gen = self.PAGE_TYPE._decompose_objects(addr, data, endness, memory=self, **kwargs)
        next(sub_gen)

        sub_data = sub_gen.send(size)
        page.store(0, sub_data, size=size, endness=endness, page_addr=page_addr, memory=self, **kwargs)
        sub_gen.close()


class ListPagesMixin(PagedMemoryMixin):
    PAGE_TYPE = ListStorageMixin
