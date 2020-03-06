import typing

from angr.storage.memory_mixins import MemoryMixin
from angr.storage.memory_mixins.paged_memory.pages import PageType, ListStorageMixin
from ....errors import SimMemoryError

class PagedMemoryMixin(MemoryMixin):
    """
    A bottom-level storage mechanism. Dispatches reads to individual pages, the type of which is the PAGE_TYPE class
    variable.
    """
    PAGE_TYPE: typing.Type[PageType] = None  # must be provided in subclass

    def __init__(self,  page_size=0x1000, default_permissions=3, permissions_map=None, **kwargs):
        super().__init__(**kwargs)
        self.page_size = page_size

        self._permissions_map = permissions_map if permissions_map is not None else {}
        self._default_permissions = default_permissions
        self._pages: typing.Dict[int, typing.Optional[PageType]] = {}

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
            if page is not None:
                page.acquire_shared()

        return o

    def _get_page(self, pageno: int, writing: bool, **kwargs) -> PageType:
        force_default = True
        # force_default means don't consult any "backers"
        # if None is stored explicitly in _pages, it means it was unmapped explicitly, so don't consult backers
        try:
            page = self._pages[pageno]
        except KeyError:
            page = None
            force_default = False

        if page is None:
            page = self._initialize_page(pageno, force_default=force_default, **kwargs)
            self._pages[pageno] = page

        if writing:
            page = page.acquire_unique()
            self._pages[pageno] = page
        return page

    def _initialize_default_page(self, pageno: int, permissions=None, **kwargs) -> PageType:
        # the difference between _initialize_default_page and _initialize_page with force_default=True
        # is that the latter may segfault. this strictly gives you a new page.
        kwargs['allow_default'] = True
        return PagedMemoryMixin._initialize_page(self, pageno, permissions=permissions, **kwargs)

    def _initialize_page(self, pageno: int, permissions=None, allow_default=True, **kwargs) -> PageType:
        if not allow_default:
            raise SimMemoryError("I have been instructed not to create a default page")
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
        if data is not None:
            sub_gen = self.PAGE_TYPE._decompose_objects(addr, data, endness, memory=self, **kwargs)
        else:
            sub_gen = self.PAGE_TYPE._zero_objects(addr, size, memory=self, **kwargs)

        next(sub_gen)

        sub_data = sub_gen.send(size)
        page.store(0, sub_data, size=size, endness=endness, page_addr=page_addr, memory=self, **kwargs)
        sub_gen.close()

    def permissions(self, addr, permissions=None, **kwargs):
        if type(addr) is not int:
            raise TypeError("addr must be an int in paged memory")
        pageno, _ = self._divide_addr(addr)
        try:
            page = self._get_page(pageno, permissions is not None, allow_default=False, **kwargs)
        except SimMemoryError as e:
            raise SimMemoryError("%#x is not mapped" % addr) from e

        result = page.permissions
        if permissions is not None:
            page.permissions = permissions
        return result

    def map_region(self, addr, length, permissions, init_zero=False, **kwargs):
        if type(addr) is not int:
            raise TypeError("addr must be an int in paged memory")
        pageno, pageoff = self._divide_addr(addr)
        size_done = 0
        max_pageno = (1 << self.state.arch.bits) // self.page_size

        while size_done < length:
            self._map_page(pageno, permissions, init_zero=init_zero, **kwargs)
            size_done += self.page_size - pageoff
            pageoff = 0
            pageno = (pageno + 1) % max_pageno

    def unmap_region(self, addr, length, **kwargs):
        if type(addr) is not int:
            raise TypeError("addr must be an int in paged memory")

        pageno, pageoff = self._divide_addr(addr)
        size_done = 0
        max_pageno = (1 << self.state.arch.bits) // self.page_size

        while size_done < length:
            self._unmap_page(pageno, **kwargs)
            size_done += self.page_size - pageoff
            pageoff = 0
            pageno = (pageno + 1) % max_pageno

    def _map_page(self, pageno, permissions, init_zero=False, **kwargs):
        # the logical flow of this shit is so confusing. this should be more compact and efficient than the old
        # simmemory model but it will require a bit of writing to solidify the contracts and allow someone
        # reading this function to actually believe that it is correctly implemented
        try:
            self._get_page(pageno, False, allow_default=False, **kwargs)
        except SimMemoryError:
            pass  # good, expected error
        else:
            raise SimMemoryError("Page is already mapped")

        page = self._initialize_default_page(pageno, permissions=permissions, **kwargs)
        self._pages[pageno] = page
        if init_zero:
            self._simple_store(page, pageno * self.page_size, None, self.page_size, 'Iend_BE', **kwargs)

    def _unmap_page(self, pageno, **kwargs):
        try:
            self._pages[pageno].release_shared()
            self._pages[pageno] = None
        except KeyError:
            pass

    def __contains__(self, addr):
        pageno, _ = self._divide_addr(addr)
        try:
            self._get_page(pageno, False, allow_default=False)
        except SimMemoryError:
            return False
        else:
            return True

    def concrete_load(self, addr, size, writing=False, **kwargs):
        pageno, offset = self._divide_addr(addr)
        remaining = self.page_size - offset
        try:
            page = self._get_page(pageno, writing, **kwargs)
        except SimMemoryError:
            return memoryview(b''), memoryview(b'')

        try:
            concrete_load = page.concrete_load
        except AttributeError:
            result = self.load(addr, size)
            if result.op == 'BVV':
                return memoryview(result.args[0].to_bytes(size, 'big')), memoryview(bytes(size))
            elif result.op == 'Concat':
                bytes_out = bytearray(size)
                bitmap_out = bytearray(size)
                bit_idx = 0
                for element in result.args:
                    byte_idx = bit_idx // 8
                    byte_size = len(element) // 8
                    if bit_idx % 8 != 0:
                        chop = 8 - bit_idx
                        bit_idx += chop
                        byte_idx += 1
                    else:
                        chop = 0

                    if element.op == 'BVV':
                        if chop:
                            element = element[len(element)-1-chop:0]

                        bytes_out[byte_idx:byte_idx+byte_size] = element.args[0].to_bytes(byte_size, 'big')
                    else:
                        for byte_i in range(byte_idx, byte_idx+byte_size):
                            bitmap_out[byte_i] = 1

                    bit_idx += len(element)
                    if bit_idx % 8 != 0:
                        bitmap_out[bit_idx // 8] = 1
                return memoryview(bytes(bytes_out)), memoryview(bytes(bitmap_out))

        else:
            return concrete_load(offset, remaining, **kwargs)



class ListPagesMixin(PagedMemoryMixin):
    PAGE_TYPE = ListStorageMixin
