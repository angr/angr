from .. import MemoryMixin


class PagedMemoryMultiValueMixin(MemoryMixin):
    """
    Implement optimizations and fast accessors for the MultiValues-variant of Paged Memory.
    """

    def load_annotations(self, addr: int, size: int, **kwargs):
        if not isinstance(size, int):
            raise TypeError("Need size to be resolved to an int by this point")

        if not isinstance(addr, int):
            raise TypeError("Need addr to be resolved to an int by this point")

        pageno, pageoff = self._divide_addr(addr)

        annotations = set()

        # fasttrack basic case
        if pageoff + size <= self.page_size:
            page = self._get_page(pageno, False, **kwargs)
            loaded = page.load(
                pageoff,
                size=size,
                page_addr=pageno * self.page_size,
                memory=self,
                cooperate=True,
                **kwargs,
            )
            for _, mos in loaded:
                if isinstance(mos, set):
                    for mo in mos:
                        annotations.update(mo.object.annotations)
                else:
                    annotations.update(mos.object.annotations)

        else:
            max_pageno = (1 << self.state.arch.bits) // self.page_size
            bytes_done = 0
            while bytes_done < size:
                page = self._get_page(pageno, False, **kwargs)
                sub_size = min(self.page_size - pageoff, size - bytes_done)
                loaded = page.load(
                    pageoff,
                    size=sub_size,
                    page_addr=pageno * self.page_size,
                    memory=self,
                    cooperate=True,
                    **kwargs,
                )
                for _, mos in loaded:
                    if isinstance(mos, set):
                        for mo in mos:
                            annotations.update(mo.object.annotations)
                    else:
                        annotations.update(mos.object.annotations)

                bytes_done += sub_size
                pageno = (pageno + 1) % max_pageno
                pageoff = 0

        return annotations
