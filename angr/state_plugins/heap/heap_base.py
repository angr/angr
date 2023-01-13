from ..plugin import SimStatePlugin

from ...errors import SimMemoryError
from .. import sim_options as opts

import logging

l = logging.getLogger("angr.state_plugins.heap.heap_base")

# TODO: derive heap location from SimOS and binary info for something more realistic (and safe?)
DEFAULT_HEAP_LOCATION = 0xC0000000
DEFAULT_HEAP_SIZE = 64 * 4096


class SimHeapBase(SimStatePlugin):
    """
    This is the base heap class that all heap implementations should subclass. It defines a few handlers for common
    heap functions (the libc memory management functions). Heap implementations are expected to override these
    functions regardless of whether they implement the SimHeapLibc interface. For an example, see the SimHeapBrk
    implementation, which is based on the original libc SimProcedure implementations.

    :ivar heap_base: the address of the base of the heap in memory
    :ivar heap_size: the total size of the main memory region managed by the heap in memory
    :ivar mmap_base: the address of the region from which large mmap allocations will be made
    """

    def __init__(self, heap_base=None, heap_size=None):
        super().__init__()

        self.heap_base = heap_base if heap_base is not None else DEFAULT_HEAP_LOCATION
        self.heap_size = heap_size if heap_size is not None else DEFAULT_HEAP_SIZE
        self.mmap_base = self.heap_base + self.heap_size * 2

    def copy(self, memo):
        o = super().copy(memo)
        o.heap_base = self.heap_base
        o.heap_size = self.heap_size
        o.mmap_base = self.mmap_base
        return o

    def _conc_alloc_size(self, sim_size):
        """
        Concretizes a size argument, if necessary, to something that makes sense when allocating space. Here we just
        maximize its potential size up to the maximum variable size specified in the libc plugin.

        TODO:
        Further consideration of the tradeoffs of this approach is probably warranted. SimHeapPTMalloc especially makes
        a lot of different concretization strategy assumptions, but this function handles one of the more important
        problems that any heap implementation will face: how to decide the amount of space to allocate upon request for
        a symbolic size. Either we do as we do here and silently constrain the amount returned to a default max value,
        or we could add a path constraint to the state to prevent exploration of any paths that would have legitimately
        occurred given a larger allocation size.

        The first approach (the silent maximum) has its benefit in that the explored state space will not be
        constrained. Sometimes this could work out, as when an allocation is returned that is smaller than requested but
        which the program doesn't end up making full use of anyways. Alternatively, this lack of fidelity could cause
        the program to overwrite other allocations made, since it should be able to assume the allocation is as large as
        it requested it be.

        The second approach (the path constraint) has its benefit in that no paths will be explored that *could* fail
        when an allocation is made too small. On the other hand, as stated above, some of these paths might not have
        failed anyways, and doing this causes us to lose the opportunity to explore those paths.

        Perhaps these behaviors could be parameterized in the future?
        """
        if self.state.solver.symbolic(sim_size):
            size = self.state.solver.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                l.warning(
                    "Allocation request of %d bytes exceeded maximum of %d bytes; allocating %d bytes",
                    size,
                    self.state.libc.max_variable_size,
                    self.state.libc.max_variable_size,
                )
                size = self.state.libc.max_variable_size
        else:
            size = self.state.solver.eval(sim_size)
        return size

    def _malloc(self, sim_size):
        """
        Handler for any libc `malloc` SimProcedure call. If the heap has faithful support for `malloc`, it ought to be
        implemented in a `malloc` function (as opposed to the `_malloc` function).

        :param sim_size: the amount of memory (in bytes) to be allocated
        """
        raise NotImplementedError(f"{self._malloc.__func__.__name__} not implemented for {self.__class__.__name__}")

    def _free(self, ptr):
        """
        Handler for any libc `free` SimProcedure call. If the heap has faithful support for `free`, it ought to be
        implemented in a `free` function (as opposed to the `_free` function).

        :param ptr: the location in memory to be freed
        """
        raise NotImplementedError(f"{self._free.__func__.__name__} not implemented for {self.__class__.__name__}")

    def _calloc(self, sim_nmemb, sim_size):
        """
        Handler for any libc `calloc` SimProcedure call. If the heap has faithful support for `calloc`, it ought to be
        implemented in a `calloc` function (as opposed to the `_calloc` function).

        :param sim_nmemb: the number of elements to allocated
        :param sim_size: the size of each element (in bytes)
        """
        raise NotImplementedError(f"{self._calloc.__func__.__name__} not implemented for {self.__class__.__name__}")

    def _realloc(self, ptr, size):
        """
        Handler for any libc `realloc` SimProcedure call. If the heap has faithful support for `realloc`, it ought to be
        implemented in a `realloc` function (as opposed to the `_realloc` function).

        :param ptr: the location in memory to be reallocated
        :param size: the new size desired for the allocation
        """
        raise NotImplementedError(f"{self._realloc.__func__.__name__} not implemented for {self.__class__.__name__}")

    def init_state(self):
        if opts.ABSTRACT_MEMORY in self.state.options:
            return

        try:
            self.state.memory.permissions(self.heap_base)
        except SimMemoryError:
            l.debug("Mapping base heap region")
            self.state.memory.map_region(self.heap_base, self.heap_size, 3)
