from __future__ import annotations

import contextlib
import logging
from typing import Self

import angr.sim_options as opts
from angr.errors import SimMemoryError
from angr.state_plugins.plugin import SimStatePlugin

l = logging.getLogger("angr.state_plugins.heap.heap_base")

# TODO: derive heap location from SimOS and binary info for something more realistic (and safe?)
DEFAULT_HEAP_LOCATION = 0xC0000000
DEFAULT_HEAP_SIZE = 0x00800000

# How much of the heap region ``init_state`` maps up front. ``heap_size`` is the *maximum* extent of the heap, not
# the amount of it that is mapped: mapping the whole thing eagerly costs one page object per page of heap (an
# UltraPage is roughly 8 KB of Python-side storage per 4 KB of address space, so ~17 MB for the default 8 MB heap),
# which is pure waste for the overwhelming majority of states, none of which ever allocate anything at all. Two
# pages are enough for the first handful of allocations; past that the mapped extent grows on demand.
HEAP_INITIAL_MAPPED_SIZE = 0x2000

# The factor by which the mapped extent of the heap grows every time an allocation runs past its end. Growing
# geometrically keeps the number of ``map_region`` calls logarithmic in the amount of heap that is actually used, so
# a program that really does allocate megabytes maps the same pages it always did, in a handful of calls.
HEAP_MAPPING_GROWTH_FACTOR = 2


class SimHeapBase(SimStatePlugin):
    """
    This is the base heap class that all heap implementations should subclass. It defines a few handlers for common
    heap functions (the libc memory management functions). Heap implementations are expected to override these
    functions regardless of whether they implement the SimHeapLibc interface. For an example, see the SimHeapBrk
    implementation, which is based on the original libc SimProcedure implementations.

    :ivar heap_base: the address of the base of the heap in memory
    :ivar heap_size: the maximum size of the main memory region managed by the heap in memory. Only the part of it
                     that has actually been handed out is mapped; see ``_ensure_mapped``.
    :ivar mmap_base: the address of the region from which large mmap allocations will be made
    """

    def __init__(self, heap_base=None, heap_size=None):
        super().__init__()

        self.heap_base = heap_base if heap_base is not None else DEFAULT_HEAP_LOCATION
        self.heap_size = heap_size if heap_size is not None else DEFAULT_HEAP_SIZE
        self.mmap_base = self.heap_base + self.heap_size * 2

        # The exclusive end address of the part of the heap region that this plugin has mapped into the memory
        # plugin. ``None`` means that this plugin does not manage the heap mapping at all - either because the
        # state uses abstract memory or because the region was already mapped by somebody else - in which case
        # nothing is ever mapped or grown here, exactly as was the case before the mapping became lazy.
        self._mapped_end: int | None = None

    def copy(self, memo) -> Self:
        o: SimHeapBase = super().copy(memo)
        o.heap_base = self.heap_base
        o.heap_size = self.heap_size
        o.mmap_base = self.mmap_base
        # the copy shares (a copy of) the memory plugin, and therefore its mapped pages, so the mapped extent
        # carries over verbatim. Forgetting this would desynchronize the extent from the memory object.
        o._mapped_end = self._mapped_end  # pylint:disable=protected-access
        return o

    def __setstate__(self, state):
        if "_mapped_end" not in state:
            # unpickling a state from before the heap mapping became lazy: back then init_state() mapped the
            # entire region up front, so that is what the mapped extent has to be
            state = dict(state)
            state["_mapped_end"] = state["heap_base"] + state["heap_size"]
        self.__dict__.update(state)

    def _combine_mapped_end(self, others):
        """
        Reconcile the mapped extent of this heap with the heaps it is being merged with. The result is deliberately
        conservative: understating the mapped extent is always safe, because growing it skips pages that already
        exist, while overstating it could leave a hole that nothing would ever map.

        This is bookkeeping, not program state, so it never counts as a merge having occurred.
        """
        ends = [self._mapped_end, *(o._mapped_end for o in others)]  # pylint: disable=protected-access
        self._mapped_end = None if any(e is None for e in ends) else min(ends)

    def _map_range(self, start, end):
        """
        Map ``[start, end)`` as read/write, tolerating pages that happen to be mapped already.

        :param start:   the first address to map (rounded down to a page boundary by the memory plugin)
        :param end:     the exclusive end of the range to map
        """
        try:
            self.state.memory.map_region(start, end - start, 3)
        except SimMemoryError:
            # something in this range is mapped already (an mmap, a gdb heap dump, a merge with a state that had
            # grown further, ...). Redo it page by page and skip whatever exists.
            page_size = getattr(self.state.memory, "page_size", 0x1000)
            for page_addr in range(start - (start % page_size), end, page_size):
                with contextlib.suppress(SimMemoryError):
                    self.state.memory.map_region(page_addr, page_size, 3)

    def _init_mapping(self):
        """
        Map the initial slice of the heap region. Called by ``init_state`` once it has determined that this plugin
        owns the mapping of the region.
        """
        self._mapped_end = self.heap_base
        self._ensure_mapped(self.heap_base + min(HEAP_INITIAL_MAPPED_SIZE, self.heap_size))

    def _ensure_mapped(self, addr):
        """
        Make sure every byte of the heap region below ``addr`` is backed by a mapped page, growing the mapped
        extent geometrically (see ``HEAP_MAPPING_GROWTH_FACTOR``) so that the number of mapping operations stays
        logarithmic in the amount of heap in use.

        Nothing past ``heap_base + heap_size`` is ever mapped: as before, ``heap_size`` bounds the region the heap
        plugin is responsible for, and allocations that run past it behave exactly as they used to.

        :param addr:    the exclusive end of the heap range that is about to be used
        """
        mapped_end = self._mapped_end
        if mapped_end is None:
            # this plugin does not manage the mapping of the heap region
            return

        region_end = self.heap_base + self.heap_size
        addr = min(addr, region_end)
        if addr <= mapped_end:
            return

        size = max(mapped_end - self.heap_base, HEAP_INITIAL_MAPPED_SIZE)
        while self.heap_base + size < addr:
            size *= HEAP_MAPPING_GROWTH_FACTOR
        new_end = min(self.heap_base + size, region_end)

        l.debug("Growing the mapped heap region to %#x (%d bytes)", new_end, new_end - self.heap_base)
        self._map_range(mapped_end, new_end)
        self._mapped_end = new_end

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
            self._init_mapping()
