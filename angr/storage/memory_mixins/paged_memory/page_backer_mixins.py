from mmap import mmap
from typing import Union, List, Generator, Tuple
import logging

import claripy
import cle

from .paged_memory_mixin import PagedMemoryMixin

l = logging.getLogger(__name__)

BackerType = Union[bytes, bytearray, List[int]]
BackerIterType = Generator[Tuple[int, BackerType], None, None]


# since memoryview isn't pickleable, we make do...
class NotMemoryview:
    def __init__(self, obj, offset, size):
        self.obj = obj
        self.offset = offset
        self.size = size

    def __getitem__(self, k):
        return memoryview(self.obj)[self.offset : self.offset + self.size][k]

    def __setitem__(self, k, v):
        memoryview(self.obj)[self.offset : self.offset + self.size][k] = v


class ClemoryBackerMixin(PagedMemoryMixin):
    def __init__(self, cle_memory_backer: Union[None, cle.Loader, cle.Clemory] = None, **kwargs):
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
            backer_iter: BackerIterType = self._clemory_backer.backers(addr)
            backer_start, backer = next(backer_iter)
        except StopIteration:
            return super()._initialize_page(pageno, **kwargs)

        if backer_start >= addr + self.page_size:
            return super()._initialize_page(pageno, **kwargs)

        # Load data from backere
        data = self._data_from_backer(addr, backer, backer_start, backer_iter)

        permissions = self._cle_permissions_lookup(addr)
        if permissions is None:
            # There is no segment mapped at the start of the page.
            # Maybe the end of the page is mapped instead?
            permissions = self._cle_permissions_lookup(addr + self.page_size - 1)

        # see if this page supports creating without copying
        if type(data) is NotMemoryview:
            try:
                new_from_shared = self.PAGE_TYPE.new_from_shared
            except AttributeError:
                data = claripy.BVV(bytes(data[:]))
            else:
                return new_from_shared(data, **self._page_kwargs(pageno, permissions))

        new_page = PagedMemoryMixin._initialize_default_page(self, pageno, permissions=permissions, **kwargs)
        new_page.store(
            0, data, size=self.page_size, page_addr=pageno * self.page_size, endness="Iend_BE", memory=self, **kwargs
        )
        return new_page

    def _data_from_backer(
        self, addr: int, backer: BackerType, backer_start: int, backer_iter: BackerIterType
    ) -> claripy.ast.BV:
        # initialize the page
        if isinstance(backer, (bytes, bytearray, mmap)):
            return self._data_from_bytes_backer(addr, backer, backer_start, backer_iter)
        elif isinstance(backer, list):
            return self._data_from_lists_backer(addr, backer, backer_start, backer_iter)
        raise TypeError("Unsupported backer type %s." % type(backer))

    def _calc_page_starts(self, addr: int, backer_start: int, backer_length: int) -> Tuple[int, int, int]:
        # lord help me. why do I keep having to write code that looks like this
        # why have I found myself entangled in a briar patch of address spaces embedded in other address spaces
        if addr >= backer_start:
            backer_first_relevant_byte = addr - backer_start
            page_first_relevant_byte = 0
        else:
            backer_first_relevant_byte = 0
            page_first_relevant_byte = backer_start - addr

        transfer_size = backer_length - backer_first_relevant_byte
        if page_first_relevant_byte + transfer_size > self.page_size:
            transfer_size = self.page_size - page_first_relevant_byte

        return backer_first_relevant_byte, page_first_relevant_byte, transfer_size

    def _data_from_bytes_backer(
        self,
        addr: int,
        backer: Union[bytes, bytearray],
        backer_start: int,
        backer_iter: Generator[Tuple[int, Union[bytes, bytearray]], None, None],
    ) -> claripy.ast.BV:
        if backer_start <= addr and backer_start + len(backer) >= addr + self.page_size:
            # fast case
            data = NotMemoryview(backer, addr - backer_start, self.page_size)
        else:
            page_data = bytearray(self.page_size)
            while backer_start < addr + self.page_size:
                backer_first_relevant_byte, page_first_relevant_byte, transfer_size = self._calc_page_starts(
                    addr, backer_start, len(backer)
                )

                backer_relevant_data = memoryview(backer)[
                    backer_first_relevant_byte : backer_first_relevant_byte + transfer_size
                ]
                page_data[page_first_relevant_byte : page_first_relevant_byte + transfer_size] = backer_relevant_data

                try:
                    backer_start, backer = next(backer_iter)
                except StopIteration:
                    break

            data = claripy.BVV(bytes(page_data))

        return data

    def _data_from_lists_backer(
        self, addr: int, backer: List[int], backer_start: int, backer_iter: Generator[Tuple[int, List[int]], None, None]
    ) -> claripy.ast.BV:
        page_data = [0] * self.page_size
        while backer_start < addr + self.page_size:
            backer_first_relevant_byte, page_first_relevant_byte, transfer_size = self._calc_page_starts(
                addr, backer_start, len(backer)
            )

            backer_relevant_data = backer[backer_first_relevant_byte : backer_first_relevant_byte + transfer_size]
            page_data[page_first_relevant_byte : page_first_relevant_byte + transfer_size] = backer_relevant_data

            try:
                backer_start, backer = next(backer_iter)
            except StopIteration:
                break

        data = claripy.Concat(*map(lambda v: claripy.BVV(v, self.state.arch.byte_width), page_data))
        return data

    def _cle_permissions_lookup(self, addr):
        if self._cle_loader is None:
            return None

        seg = self._cle_loader.find_segment_containing(addr, skip_pseudo_objects=False)
        if seg is None:
            return None

        out = 0
        if seg.is_readable:
            out |= 1
        if seg.is_writable:
            out |= 2
        if seg.is_executable:
            out |= 4

        return out


class ConcreteBackerMixin(ClemoryBackerMixin):
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

        if self.state.project.concrete_target:
            l.debug("Fetching data from concrete target")
            data = claripy.BVV(
                bytearray(self.state.project.concrete_target.read_memory(pageno * self.page_size, self.page_size)),
                self.page_size * 8,
            )
        else:
            # the concrete backer only is here to support concrete loading, defer back to the CleMemoryBacker
            return super()._initialize_page(pageno, **kwargs)

        permissions = self._cle_permissions_lookup(addr)

        # see if this page supports creating without copying
        if type(data) is NotMemoryview:
            try:
                new_from_shared = self.PAGE_TYPE.new_from_shared
            except AttributeError:
                data = claripy.BVV(bytes(data[:]))
            else:
                return new_from_shared(data, **self._page_kwargs(pageno, permissions))

        new_page = PagedMemoryMixin._initialize_default_page(self, pageno, permissions=permissions, **kwargs)
        new_page.store(
            0, data, size=self.page_size, page_addr=pageno * self.page_size, endness="Iend_BE", memory=self, **kwargs
        )
        return new_page


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
                    kwargs["allow_default"] = True
                    new_page = PagedMemoryMixin._initialize_default_page(self, pageno, **kwargs)
                new_page.store(
                    addr % self.page_size,
                    claripy.BVV(byte[0] if type(byte) is bytes else byte, self.state.arch.byte_width),
                    size=1,
                    endness="Iend_BE",
                    page_addr=page_addr,
                    memory=self,
                    **kwargs,
                )

        if new_page is None:
            return super()._initialize_page(pageno, **kwargs)

        return new_page
