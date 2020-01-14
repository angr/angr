import logging

from .paged_memory_mixin import PagedMemoryMixin

l = logging.getLogger(__name__)



class ClemoryBackerMixin(PagedMemoryMixin):
    def __init__(self, clemory=None, **kwargs):
        super().__init__(**kwargs)
        self.clemory = clemory

    def copy(self, memo):
        o = super().copy(memo)
        o.clemory = self.clemory
        return o

    def _initialize_page(self, pageno, **kwargs):
        if self.clemory is None:
            return super()._initialize_page(pageno, **kwargs)

        addr = pageno * self.page_size

        try:
            backer_start, backer = next(self.clemory.memory.backers(addr))
        except StopIteration:
            return super()._initialize_page(pageno, **kwargs)

        if backer_start > addr:
            return super()._initialize_page(pageno, **kwargs)

        if backer_start + len(backer) < addr + self.page_size:
            l.info("Clemory backer somehow doesn't provide a full page? padding with null bytes")
            data = memoryview(backer[addr - backer_start:].ljust(self.page_size, b'\0'))
            refs = 1
        else:
            data = memoryview(backer)[addr-backer_start:addr-backer_start+self.page_size]
            refs = 2

        new_page = self.PAGE_TYPE()
        new_page.refcount = refs
        # TODO: what to do about the type of data? should the conversion happen here or below?
        new_page.store(0, data, size=self.page_size, endness='Iend_BE')
        return new_page