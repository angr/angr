import logging
import claripy
import cle

from .paged_memory_mixin import PagedMemoryMixin

l = logging.getLogger(__name__)



class ClemoryBackerMixin(PagedMemoryMixin):
    def __init__(self, cle_memory_backer=None, **kwargs):
        super().__init__(**kwargs)

        if isinstance(cle_memory_backer, cle.Loader):
            self._cle_loader = cle_memory_backer
            self._clemory_backer = cle_memory_backer.memory
        elif isinstance(cle_memory_backer, cle.Clemory):
            self._cle_loader = None
            self._clemory_backer = cle_memory_backer
        else:
            self._cle_loader = None
            self._clemory_backer = None

    def copy(self, memo):
        o = super().copy(memo)
        o._clemory_backer = self._clemory_backer
        o._cle_loader = self._cle_loader
        return o

    def _initialize_page(self, pageno, force_default=False, **kwargs):
        if self._clemory_backer is None or force_default:
            return super()._initialize_page(pageno, **kwargs)

        addr = pageno * self.page_size

        try:
            backer_iter = self._clemory_backer.backers(addr)
            backer_start, backer = next(backer_iter)
        except StopIteration:
            return super()._initialize_page(pageno, **kwargs)

        if backer_start >= addr + self.page_size:
            return super()._initialize_page(pageno, **kwargs)

        if backer_start <= addr and backer_start + len(backer) > addr + self.page_size:
            # fast case
            data = memoryview(backer)[addr-backer_start:addr-backer_start+self.page_size]
        else:
            page_data = bytearray(self.page_size)
            while backer_start < addr + self.page_size:
                # lord help me. why do I keep having to write code that looks like this
                # why have I found myself entangled in a briar patch of address spaces embedded in other address spaces
                if addr >= backer_start:
                    backer_first_relevant_byte = addr - backer_start
                    page_first_relevant_byte = 0
                else:
                    backer_first_relevant_byte = 0
                    page_first_relevant_byte = backer_start - addr

                transfer_size = len(backer) - backer_first_relevant_byte
                if page_first_relevant_byte + transfer_size > self.page_size:
                    transfer_size = self.page_size - page_first_relevant_byte

                backer_relevant_data = memoryview(backer)[backer_first_relevant_byte:backer_first_relevant_byte+transfer_size]
                page_data[page_first_relevant_byte:page_first_relevant_byte+transfer_size] = backer_relevant_data

                try:
                    backer_start, backer = next(backer_iter)
                except StopIteration:
                    break

            data = claripy.BVV(bytes(page_data))

        permissions = self._cle_permissions_lookup(addr)

        # TODO: if any pages implement new_from_shared it could save us a lot of copying
        if type(data) is memoryview:
            try:
                new_from_shared = self.PAGE_TYPE.new_from_shared
            except AttributeError:
                data = claripy.BVV(bytes(data))
            else:
                if permissions is None:
                    permissions = self._default_permissions
                return new_from_shared(data, memory_id='%s_%d' % (self.id, pageno), memory=self, permissions=permissions)

        new_page = PagedMemoryMixin._initialize_default_page(self, pageno, permissions=permissions, **kwargs)
        self._simple_store(new_page, addr, data, self.page_size, 'Iend_BE', **kwargs)
        return new_page

    def _cle_permissions_lookup(self, addr):
        if self._cle_loader is None:
            return None

        seg = self._cle_loader.find_segment_containing(addr, skip_pseudo_objects=False)
        if seg is None:
            return None

        out = 0
        if seg.is_readable: out |= 1
        if seg.is_writable: out |= 2
        if seg.is_executable: out |= 4

        return out

class DictBackerMixin(PagedMemoryMixin):
    def __init__(self, dict_memory_backer=None, **kwargs):
        super().__init__(**kwargs)
        self._dict_memory_backer = dict_memory_backer

    def copy(self, memo):
        o = super().copy(memo)
        o._dict_memory_backer = self._dict_memory_backer
        return o

    def _initialize_page(self, pageno: int, force_default=False, **kwargs):
        page_addr = pageno * self.page_size

        if self._dict_memory_backer is None or force_default:
            return super()._initialize_page(pageno, **kwargs)

        new_page = None

        for addr, byte in self._dict_memory_backer.items():
            if page_addr <= addr < page_addr + self.page_size:
                if new_page is None:
                    kwargs['allow_default'] = True
                    new_page = PagedMemoryMixin._initialize_default_page(self, pageno, **kwargs)
                self._simple_store(new_page, addr, claripy.BVV(byte[0] if type(byte) is bytes else byte, self.state.arch.byte_width), 1, 'Iend_BE', **kwargs)

        if new_page is None:
            return super()._initialize_page(pageno, **kwargs)

        return new_page
