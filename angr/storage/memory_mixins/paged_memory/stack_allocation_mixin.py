import logging

from .paged_memory_mixin import PagedMemoryMixin
from ....errors import SimSegfaultException, SimMemoryError

l = logging.getLogger(__name__)

class StackAllocationMixin(PagedMemoryMixin):
    """
    This mixin adds automatic allocation for a stack region based on the stack_end and stack_size parameters.
    """
    # TODO: multiple stacks. this scheme should scale p well
    # TODO tbh this should be handled by an actual fault handler in simos or something
    def __init__(self, stack_end=None, stack_size=None, stack_perms=None, **kwargs):
        super().__init__(**kwargs)
        self._red_pageno = (stack_end - 1) // self.page_size if stack_end is not None else None
        self._remaining_stack = stack_size
        self._stack_perms = stack_perms

    def copy(self, memo):
        o = super().copy(memo)
        o._red_pageno = self._red_pageno
        o._remaining_stack = self._remaining_stack
        o._stack_perms = self._stack_perms
        return o

    def allocate_stack_pages(self, addr: int, size: int, **kwargs):
        """
        Pre-allocates pages for the stack without triggering any logic related to reading from them.

        :param addr: The highest address that should be mapped
        :param size: The number of bytes to be allocated. byte 1 is the one at addr, byte 2 is the one before that, and so on.
        :return: A list of the new page objects
        """
        # weird off-by-ones here. we want to calculate the last byte requested, find its pageno, and then use that to determine what the last page allocated will be and then how many pages are touched
        pageno = addr // self.page_size
        if pageno != self._red_pageno:
            raise SimMemoryError("Trying to allocate stack space in a place that isn't the top of the stack")
        num = pageno - ((addr - size + 1) // self.page_size) + 1

        result = []
        for _ in range(num):
            new_red_pageno = (self._red_pageno - 1) % ((1 << self.state.arch.bits) // self.page_size)
            if new_red_pageno in self._pages:
                raise SimSegfaultException(self._red_pageno * self.page_size, "stack collided with heap")

            if self._remaining_stack is not None and self._remaining_stack < self.page_size:
                raise SimSegfaultException(self._red_pageno * self.page_size, "exhausted stack quota")

            l.debug("Allocating new stack page at %#x", self._red_pageno * self.page_size)
            result.append(PagedMemoryMixin._initialize_default_page(self, self._red_pageno, permissions=self._stack_perms, **kwargs))
            self._pages[self._red_pageno] = result[-1]

            self._red_pageno = new_red_pageno
            if self._remaining_stack is not None:
                self._remaining_stack -= self.page_size

        return result

    def _initialize_page(self, pageno: int, **kwargs):
        if pageno != self._red_pageno:
            return super()._initialize_page(pageno, **kwargs)

        return self.allocate_stack_pages((pageno + 1) * self.page_size - 1, self.page_size)[0]
