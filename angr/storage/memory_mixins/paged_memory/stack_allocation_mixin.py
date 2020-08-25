import logging

from .paged_memory_mixin import PagedMemoryMixin
from ....errors import SimSegfaultException

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

    def _initialize_page(self, pageno: int, **kwargs):
        if pageno != self._red_pageno:
            return super()._initialize_page(pageno, **kwargs)

        new_red_pageno = (pageno - 1) % ((1 << self.state.arch.bits) // self.page_size)
        if new_red_pageno in self._pages:
            raise SimSegfaultException(pageno * self.page_size, "stack collided with heap")

        if self._remaining_stack is not None and self._remaining_stack < self.page_size:
            raise SimSegfaultException(pageno * self.page_size, "exhausted stack quota")

        self._red_pageno = new_red_pageno
        if self._remaining_stack is not None:
            self._remaining_stack -= self.page_size

        l.debug("Allocating new stack page at %#x", pageno * self.page_size)

        new_page = PagedMemoryMixin._initialize_default_page(self, pageno, permissions=self._stack_perms, **kwargs)
        return new_page
