import logging
import claripy
import cle

from .paged_memory_mixin import PagedMemoryMixin

l = logging.getLogger(__name__)



class ClemoryBackerMixin(PagedMemoryMixin):
    def __init__(self, memory_backer=None, **kwargs):
        if memory_backer is None or type(memory_backer) is cle.Clemory:
            super().__init__(**kwargs)
            self._clemory_backer = memory_backer
        else:
            super().__init__(memory_backer=memory_backer, **kwargs)
            self._clemory_backer = None

    def copy(self, memo):
        o = super().copy(memo)
        o._clemory_backer = self._clemory_backer
        return o

    def _initialize_page(self, pageno, **kwargs):
        if self._clemory_backer is None:
            return super()._initialize_page(pageno, **kwargs)

        addr = pageno * self.page_size

        try:
            backer_start, backer = next(self._clemory_backer.memory.backers(addr))
        except StopIteration:
            return super()._initialize_page(pageno, **kwargs)

        if backer_start > addr:
            return super()._initialize_page(pageno, **kwargs)

        if backer_start + len(backer) < addr + self.page_size:
            l.info("Clemory backer somehow doesn't provide a full page? padding with null bytes")
            data = claripy.BVV(bytes(backer[addr - backer_start:].ljust(self.page_size, b'\0')))
        else:
            data = memoryview(backer)[addr-backer_start:addr-backer_start+self.page_size]

        # TODO: if any pages implement new_from_shared it could save us a lot of copying
        if type(data) is memoryview:
            try:
                new_from_shared = self.PAGE_TYPE.new_from_shared
            except AttributeError:
                data = claripy.BVV(bytes(data))
            else:
                return new_from_shared(data, memory_id='%s_%d' % (self.id, pageno), memory=self)

        new_page = PagedMemoryMixin._initialize_page(self, pageno, **kwargs)
        self._simple_store(new_page, addr, data, self.page_size, 'Iend_BE', **kwargs)
        return new_page

class DictBackerMixin(PagedMemoryMixin):
    def __init__(self, memory_backer=None, **kwargs):
        if memory_backer is None or type(memory_backer) is dict:
            super().__init__(**kwargs)
            self._dict_backer = memory_backer
        else:
            super().__init__(memory_backer=memory_backer, **kwargs)
            self._dict_backer = None

    def copy(self, memo):
        o = super().copy(memo)
        o._dict_backer = self._dict_backer
        return o

    def _initialize_page(self, pageno: int, **kwargs):
        page_addr = pageno * self.page_size

        if self._dict_backer is None:
            return super()._initialize_page(pageno, **kwargs)

        new_page = None

        for addr, byte in self._dict_backer.items():
            if page_addr <= addr < page_addr + self.page_size:
                if new_page is None:
                    new_page = PagedMemoryMixin._initialize_page(self, pageno, **kwargs)
                self._simple_store(new_page, addr, claripy.BVV(byte[0] if type(byte) is bytes else byte, self.state.arch.byte_width), 1, 'Iend_BE', **kwargs)

        if new_page is None:
            return super()._initialize_page(pageno, **kwargs)

        return new_page
