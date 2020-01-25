from .paged_memory_mixin import PagedMemoryMixin
from ....errors import SimSegfaultException

class StackAllocationMixin(PagedMemoryMixin):
    """
    This mixin adds automatic allocation for a stack region based on the stack_end and stack_size parameters.
    """
    # TODO: multiple stacks. this scheme should scale p well
    # TODO tbh this should be handled by an actual fault handler in simos or something
    def __init__(self, stack_end=None, stack_size=None, stack_perms=3, **kwargs):
        super().__init__(**kwargs)
        self._red_page = (stack_end - 1) // self.page_size if stack_end is not None else None
        self._remaining_stack = stack_size // self.page_size if stack_size is not None else None
        self._stack_perms = stack_perms

    def copy(self, memo):
        o = super().copy(memo)
        o._red_page = self._red_page
        o._remaining_stack = self._remaining_stack
        o._stack_perms = self._stack_perms
        return o

    def _initialize_page(self, pageno: int, **kwargs):
        if pageno != self._red_page:
            return super()._initialize_page(pageno, **kwargs)

        new_red_page = ((pageno - 1) % ((1 << self.state.arch.bits) // self.page_size) - 1)
        if new_red_page in self._pages:
            raise SimSegfaultException(pageno * self.page_size, "stack collided with heap")

        if self._remaining_stack == 0:
            raise SimSegfaultException(pageno * self.page_size, "exhausted stack quota")

        self._red_page = new_red_page
        self._remaining_stack -= 1

        new_page = PagedMemoryMixin._initialize_page(self, pageno, **kwargs)
        new_page.permissions = self._stack_perms
        return new_page
