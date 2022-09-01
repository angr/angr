import cffi
from typing import Tuple, Type, Dict, Optional, Iterable, Set, Any
import logging
from collections import defaultdict

import claripy

from angr.storage.memory_mixins import MemoryMixin
from angr.storage.memory_mixins.paged_memory.pages import PageType, ListPage, UltraPage, MVListPage
from ....errors import SimMemoryError

# yeet
ffi = cffi.FFI()

l = logging.getLogger(__name__)


class PagedMemoryMixin(MemoryMixin):
    """
    A bottom-level storage mechanism. Dispatches reads to individual pages, the type of which is the PAGE_TYPE class
    variable.
    """
    SUPPORTS_CONCRETE_LOAD = True
    PAGE_TYPE: Type[PageType] = None  # must be provided in subclass

    def __init__(self,  page_size=0x1000, default_permissions=3, permissions_map=None, page_kwargs=None, **kwargs):
        super().__init__(**kwargs)
        self.page_size = page_size
        self._extra_page_kwargs = page_kwargs if page_kwargs is not None else {}

        self._permissions_map = permissions_map if permissions_map is not None else {}
        self._default_permissions = default_permissions
        self._pages: Dict[int, Optional[PageType]] = {}

    @MemoryMixin.memo
    def copy(self, memo):
        o = super().copy(memo)

        o.page_size = self.page_size
        o._extra_page_kwargs = self._extra_page_kwargs

        o._default_permissions = self._default_permissions
        o._permissions_map = self._permissions_map
        o._pages = dict(self._pages)

        for page in o._pages.values():
            if page is not None:
                page.acquire_shared()

        return o

    def __del__(self):
        # a thought: we could support mapping pages in multiple places in memory if here we just kept a set of released
        # page ids and never released any page more than once
        for page in self._pages.values():
            if page is not None:
                page.release_shared()

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

        return self.PAGE_TYPE(**self._page_kwargs(pageno, permissions))  # pylint:disable=not-callable

    def _page_kwargs(self, pageno, permissions):
        # permissions lookup: let permissions arg override everything else
        # then try the permissions map
        # then fall back to the default permissions
        if permissions is None:
            permissions = self._default_permissions
            addr = pageno * self.page_size

            for (start, end), perms in self._permissions_map.items():
                if start <= addr <= end:
                    permissions = perms
                    break

        return dict(
            memory=self,
            memory_id='%s_%d' % (self.id, pageno),
            permissions=permissions,
            **self._extra_page_kwargs
        )

    def _divide_addr(self, addr: int) -> Tuple[int, int]:
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
            page = self._get_page(pageno, False, **kwargs)
            vals.append(page.load(pageoff, size=size, endness=endness, page_addr=pageno*self.page_size, memory=self, cooperate=True, **kwargs))

        else:
            max_pageno = (1 << self.state.arch.bits) // self.page_size
            bytes_done = 0
            while bytes_done < size:
                page = self._get_page(pageno, False, **kwargs)
                sub_size = min(self.page_size-pageoff, size-bytes_done)
                vals.append(page.load(pageoff, size=sub_size, endness=endness, page_addr=pageno*self.page_size, memory=self, cooperate=True, **kwargs))

                bytes_done += sub_size
                pageno = (pageno + 1) % max_pageno
                pageoff = 0

        out = self.PAGE_TYPE._compose_objects(vals, size, endness, memory=self, **kwargs)
        l.debug("%s.load(%#x, %d, %s) = %s", self.id, addr, size, endness, out)
        return out

    def store(self, addr: int, data, size: int=None, endness=None, **kwargs):
        if endness is None:
            endness = self.endness

        if type(size) is not int:
            raise TypeError("Need size to be resolved to an int by this point")

        if type(addr) is not int:
            raise TypeError("Need addr to be resolved to an int by this point")

        # l.debug("%s.store(%#x, %s, %s)", self.id, addr, data, endness)

        pageno, pageoff = self._divide_addr(addr)
        sub_gen = self.PAGE_TYPE._decompose_objects(addr, data, endness, memory=self, **kwargs)
        next(sub_gen)

        # fasttrack basic case
        if pageoff + size <= self.page_size:
            written_size = 0
            while written_size < size:
                sub_data, sub_data_base, sub_data_size = sub_gen.send(size - written_size)
                page = self._get_page(pageno, True, **kwargs)
                sub_data_size = min(sub_data_size, size - written_size)
                page.store(pageoff + written_size, sub_data, size=sub_data_size, endness=endness,
                           page_addr=pageno*self.page_size, memory=self, cooperate=True, **kwargs)
                written_size += sub_data_size
            sub_gen.close()
            return

        max_pageno = (1 << self.state.arch.bits) // self.page_size
        bytes_done = 0
        while bytes_done < size:
            # if we really want we could add an optimization where writing an entire page creates a new page object
            # instead of overwriting the old one. would have to be careful about maintaining the contract for _get_page
            page = self._get_page(pageno, True, **kwargs)
            sub_size = min(self.page_size-pageoff, size-bytes_done)
            written_size = 0

            while written_size < sub_size:
                sub_data, sub_data_base, sub_data_size = sub_gen.send(sub_size - written_size)
                # calculate the actual to write
                if sub_data_base < pageno * self.page_size:
                    # if the memory object starts before the page, adjust the sub_data_size accordingly
                    sub_data_size = sub_data_base + sub_data_size - pageno * self.page_size
                sub_data_size = min(sub_data_size, sub_size - written_size)
                page.store(pageoff + written_size, sub_data, size=sub_data_size, endness=endness,
                           page_addr=pageno*self.page_size, memory=self, cooperate=True, **kwargs)
                written_size += sub_data_size

            bytes_done += sub_size
            pageno = (pageno + 1) % max_pageno
            pageoff = 0

        sub_gen.close()

    def erase(self, addr, size=None, **kwargs) -> None:
        if type(size) is not int:
            raise TypeError("Need size to be resolved to an int by this point")

        if type(addr) is not int:
            raise TypeError("Need addr to be resolved to an int by this point")

        pageno, pageoff = self._divide_addr(addr)
        max_pageno = (1 << self.state.arch.bits) // self.page_size
        bytes_done = 0
        while bytes_done < size:
            page = self._get_page(pageno, True, **kwargs)
            sub_size = min(self.page_size - pageoff, size - bytes_done)
            page.erase(pageoff, sub_size, memory=self, **kwargs)
            bytes_done += sub_size
            pageno = (pageno + 1) % max_pageno
            pageoff = 0

    def merge(self, others: Iterable['PagedMemoryMixin'], merge_conditions, common_ancestor=None) -> bool:
        changed_pages_and_offsets: Dict[int,Optional[Set[int]]] = {}
        for o in others:
            for changed_page, changed_offsets in self.changed_pages(o).items():
                if changed_offsets is None:
                    changed_pages_and_offsets[changed_page] = None
                elif changed_page not in changed_pages_and_offsets: # changed_offsets is a set of offsets (ints)
                    # update our dict
                    changed_pages_and_offsets[changed_page] = changed_offsets
                elif changed_pages_and_offsets[changed_page] is None: # changed_page in our dict
                    # in at least one `other` memory can we not determine the changed offsets
                    # do nothing
                    pass
                else:
                    # union changed_offsets with known ones
                    changed_pages_and_offsets[changed_page] = \
                        changed_pages_and_offsets[changed_page].union(changed_offsets)

        if merge_conditions is None:
            merge_conditions = [None] * (len(list(others)) + 1)

        merged_bytes = set()
        for page_no in sorted(changed_pages_and_offsets.keys()):
            l.debug("... on page %x", page_no)

            page = self._get_page(page_no, True)
            other_pages = [ ]

            for o in others:
                if page_no in o._pages:
                    other_pages.append(o._get_page(page_no, False))

            page_addr = page_no * self.page_size
            changed_offsets = changed_pages_and_offsets[page_no]
            merged_offsets = page.merge(other_pages, merge_conditions, page_addr=page_addr, memory=self,
                                        changed_offsets=changed_offsets)
            for off in merged_offsets:
                merged_bytes.add(page_addr + off)

        return bool(merged_bytes)

    def permissions(self, addr, permissions=None, **kwargs):
        if type(addr) is not int:
            raise TypeError("addr must be an int in paged memory")
        pageno, _ = self._divide_addr(addr)
        try:
            page = self._get_page(pageno, permissions is not None, allow_default=False, **kwargs)
        except SimMemoryError as e:
            raise SimMemoryError("%#x is not mapped" % addr) from e

        if type(permissions) is int:
            permissions = self.state.solver.BVV(permissions, 3)

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
            raise SimMemoryError("Page is already mapped", pageno * self.page_size)

        page = self._initialize_default_page(pageno, permissions=permissions, **kwargs)
        self._pages[pageno] = page
        if init_zero:
            page.store(0, None, size=self.page_size, endness='Iend_BE', page_addr=pageno*self.page_size, memory=self,
                       **kwargs)

    def _unmap_page(self, pageno, **kwargs):  # pylint:disable=unused-argument
        try:
            if self._pages[pageno] is not None:
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

    def _load_to_memoryview(self, addr, size, with_bitmap):
        result = self.load(addr, size, endness='Iend_BE')
        if result.op == 'BVV':
            if with_bitmap:
                return memoryview(result.args[0].to_bytes(size, 'big')), memoryview(bytes(size))
            else:
                return memoryview(result.args[0].to_bytes(size, 'big'))
        elif result.op == 'Concat':
            bytes_out = bytearray(size)
            bitmap_out = bytearray(size)
            bit_idx = 0
            byte_width = self.state.arch.byte_width
            for element in result.args:
                byte_idx = bit_idx // byte_width
                byte_size = len(element) // byte_width

                if len(element) + bit_idx < (byte_idx + 1) * byte_width:
                    # the current element is not long enough to reach the next byte
                    # it is impossible to have multiple concrete BVV objects straddling byte boundaries
                    bit_idx += len(element)
                    if not with_bitmap:
                        return memoryview(bytes(bytes_out))[:byte_idx]
                    bitmap_out[byte_idx] = 1
                    continue

                if bit_idx % byte_width != 0:
                    # if the current element has at least byte_width bits, the top `hi_chop` bits should be removed
                    hi_chop = byte_width - (bit_idx % byte_width)
                else:
                    hi_chop = 0

                if (bit_idx + len(element)) % byte_width != 0:
                    # if the current element does not have enough bits to extend to the next byte boundary, the
                    # bottom `lo_chop` bits should be removed
                    lo_chop = (bit_idx + len(element)) % byte_width
                else:
                    lo_chop = 0

                if hi_chop + lo_chop == len(element):
                    # the entire element will be removed
                    bit_idx += len(element)
                    if not with_bitmap:
                        return memoryview(bytes(bytes_out))[:byte_idx]
                    bitmap_out[byte_idx] = 1
                    continue

                if hi_chop:
                    bitmap_out[byte_idx] = 1
                    byte_idx += 1

                if element.op == 'BVV':
                    chopped = element
                    if hi_chop:
                        chopped = chopped[len(chopped) - 1 - hi_chop:0]
                    if lo_chop:
                        chopped = chopped[:lo_chop]

                    if len(chopped) > 0:
                        bytes_out[byte_idx:byte_idx + byte_size] = chopped.args[0].to_bytes(byte_size, 'big')
                else:
                    if not with_bitmap:
                        return memoryview(bytes(bytes_out))[:byte_idx]
                    for byte_i in range(byte_idx, byte_idx + byte_size):
                        bitmap_out[byte_i] = 1

                bit_idx += len(element)
                if bit_idx % byte_width != 0:
                    if not with_bitmap:
                        return memoryview(bytes(bytes_out))[:bit_idx // byte_width]
                    bitmap_out[bit_idx // byte_width] = 1
            if with_bitmap:
                return memoryview(bytes(bytes_out)), memoryview(bytes(bitmap_out))
            else:
                return memoryview(bytes(bytes_out))
        else:
            if with_bitmap:
                return memoryview(bytes(size)), memoryview(b'\x01' * size)
            else:
                return memoryview(b'')

    def concrete_load(self, addr, size, writing=False, with_bitmap=False, **kwargs):
        pageno, offset = self._divide_addr(addr)
        subsize = min(size, self.page_size - offset)
        try:
            page = self._get_page(pageno, writing, **kwargs)
        except SimMemoryError:
            if with_bitmap:
                return memoryview(b''), memoryview(b'')
            else:
                return memoryview(b'')

        if not page.SUPPORTS_CONCRETE_LOAD:
            # the page does not support concrete_load
            return self._load_to_memoryview(addr, size, with_bitmap)

        data, bitmap = page.concrete_load(offset, subsize, **kwargs)
        if with_bitmap:
            return data, bitmap

        # everything from here on out has exactly one goal: to maximize the amount of concrete data
        # we can return (up to the limit!)
        for i, byte in enumerate(bitmap):
            if byte != 0:
                break
        else:
            i = len(bitmap)

        if i != subsize:
            return data[:i]

        size -= subsize

        physically_adjacent = True
        while size:
            offset = 0
            max_pageno = (1 << self.state.arch.bits) // self.page_size
            pageno = (pageno + 1) % max_pageno
            subsize = min(size, self.page_size)

            try:
                page = self._get_page(pageno, writing, **kwargs)
                concrete_load = page.concrete_load
            except (SimMemoryError, AttributeError):
                break
            else:

                newdata, bitmap = concrete_load(offset, subsize, **kwargs)
                for i, byte in enumerate(bitmap):
                    if byte != 0:
                        break
                else:
                    i = len(bitmap)

                # magic: check if the memory regions are physically adjacent
                if physically_adjacent and ffi.cast(ffi.BVoidP, ffi.from_buffer(data)) + len(data) == ffi.cast(ffi.BVoidP, ffi.from_buffer(newdata)):
                    # magic: generate a new memoryview which contains the two physically adjacent regions
                    obj = data.obj
                    if obj is None:
                        # XXX HACK FOR PYPY
                        obj = page.concrete_data.obj
                    data_offset = ffi.cast(ffi.BVoidP, ffi.from_buffer(data)) - ffi.cast(ffi.BVoidP,
                                                                                         ffi.from_buffer(obj))
                    data = memoryview(obj)[data_offset:data_offset + len(data) + i]
                else:
                    # they are not adjacent - create a new bytearray to hold data
                    physically_adjacent = False
                    bytes_out = bytearray(data) + bytearray(newdata[:i])
                    data = memoryview(bytes_out)

                if i != subsize:
                    break

                size -= subsize

        return data

    def changed_bytes(self, other) -> Set[int]:
        my_pages = set(self._pages)
        other_pages = set(other._pages)
        intersection = my_pages.intersection(other_pages)
        difference = my_pages.difference(other_pages)

        changes = set()
        for pageno in difference:
            changes.update(range(pageno * self.page_size, (pageno + 1) * self.page_size))

        for pageno in intersection:
            my_page = self._pages[pageno]
            other_page = other._pages[pageno]

            if (my_page is None) ^ (other_page is None):
                changes.update(range(pageno * self.page_size, (pageno + 1) * self.page_size))
            elif my_page is None:
                pass
            elif my_page is other_page:
                pass
            else:
                changes.update(my_page.changed_bytes(other_page, page_addr=pageno * self.page_size))

        return changes

    def changed_pages(self, other) -> Dict[int,Optional[Set[int]]]:
        my_pages = set(self._pages)
        other_pages = set(other._pages)
        intersection = my_pages.intersection(other_pages)
        difference = my_pages.symmetric_difference(other_pages)
        
        changes: Dict[int,Optional[Set[int]]] = dict((d, None) for d in difference)

        for pageno in intersection:
            my_page = self._pages[pageno]
            other_page = other._pages[pageno]

            if (my_page is None) ^ (other_page is None):
                changes[pageno] = None
            elif my_page is None:
                pass
            elif my_page is other_page:
                pass
            else:
                changed_offsets = my_page.changed_bytes(other_page, page_addr=pageno * self.page_size)
                if changed_offsets:
                    changes[pageno] = changed_offsets

        return changes

    def _replace_all(self, addrs: Iterable[int], old: claripy.ast.BV, new: claripy.ast.BV):

        page_offsets: Dict[Set[int]] = defaultdict(set)
        for addr in addrs:
            page_no, page_offset = self._divide_addr(addr)
            page_offsets[page_no].add(page_offset)

        for page_no, offsets in page_offsets.items():
            page = self._pages[page_no]
            page = page.acquire_unique()
            self._pages[page_no] = page
            page.replace_all_with_offsets(offsets, old, new, memory=self)

    def copy_contents(self, dst, src, size, condition=None, **kwargs):
        data = self.load(src, size, **kwargs)
        self.store(dst, data, size, **kwargs)

    def flush_pages(self, white_list):
        """
        Flush all pages not included in the `white_list` by removing their pages. Note, this will not wipe them
        from memory if they were backed by a memory_backer, it will simply reset them to their initial state.
        Returns the list of pages that were cleared consisting of `(addr, length)` tuples.
        :param white_list: white list of regions in the form of (start, end) to exclude from the flush
        :return: a list of memory page ranges that were flushed
        :rtype: list
        """
        white_list_page_number = []

        for addr in white_list:
            for page_addr in range(addr[0], addr[1], self.page_size):
                pageno, _ = self.state.memory._divide_addr(page_addr)
                white_list_page_number.append(pageno)

        new_page_dict = {}
        flushed = []

        # cycle over all the keys ( the page number )
        for pageno, page in self._pages.items():
            if pageno in white_list_page_number:
                #l.warning("Page " + str(pageno) + " not flushed!")
                new_page_dict[pageno] = page
            else:
                #l.warning("Page " + str(pageno) + " flushed!")
                flushed.append((pageno, self.page_size))
        self._pages = new_page_dict
        return flushed


class LabeledPagesMixin(PagedMemoryMixin):
    def load_with_labels(self, addr: int, size: int=None, endness=None, **kwargs) -> Tuple[claripy.ast.Base,Tuple[Tuple[int,int,int,Any]]]:
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
            page = self._get_page(pageno, False, **kwargs)
            vals.append(page.load(pageoff, size=size, endness=endness, page_addr=pageno*self.page_size, memory=self, cooperate=True, **kwargs))

        else:
            max_pageno = (1 << self.state.arch.bits) // self.page_size
            bytes_done = 0
            while bytes_done < size:
                page = self._get_page(pageno, False, **kwargs)
                sub_size = min(self.page_size-pageoff, size-bytes_done)
                vals.append(page.load(pageoff, size=sub_size, endness=endness, page_addr=pageno*self.page_size, memory=self, cooperate=True, **kwargs))

                bytes_done += sub_size
                pageno = (pageno + 1) % max_pageno
                pageoff = 0

        labels = [ ]
        out = self.PAGE_TYPE._compose_objects(vals, size, endness, memory=self, labels=labels, **kwargs)
        l.debug("%s.load_with_labels(%#x, %d, %s) = %s", self.id, addr, size, endness, out)
        return out, tuple(labels)


class ListPagesMixin(PagedMemoryMixin):
    PAGE_TYPE = ListPage


class MVListPagesMixin(PagedMemoryMixin):
    PAGE_TYPE = MVListPage

    def __init__(self, *args, skip_missing_values_during_merging=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.skip_missing_values_during_merging = skip_missing_values_during_merging

    @MemoryMixin.memo
    def copy(self, memo) -> 'MVListPagesMixin':
        r = super().copy(memo)
        r.skip_missing_values_during_merging = self.skip_missing_values_during_merging
        return r


class ListPagesWithLabelsMixin(
    LabeledPagesMixin,
    ListPagesMixin,
):
    pass


class MVListPagesWithLabelsMixin(
    LabeledPagesMixin,
    MVListPagesMixin,
):
    pass


class UltraPagesMixin(PagedMemoryMixin):
    PAGE_TYPE = UltraPage
