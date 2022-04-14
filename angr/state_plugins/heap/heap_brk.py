from angr.errors import SimSolverError
from ..plugin import SimStatePlugin
from . import SimHeapBase

import logging

l = logging.getLogger(__name__)

class SimHeapBrk(SimHeapBase):
    """
    SimHeapBrk represents a trivial heap implementation based on the Unix `brk` system call. This type of heap stores
    virtually no metadata, so it is up to the user to determine when it is safe to release memory. This also means that
    it does not properly support standard heap operations like `realloc`.

    This heap implementation is a holdover from before any more proper implementations were modelled. At the time,
    various libc (or win32) SimProcedures handled the heap in the same way that this plugin does now. To make future
    heap implementations plug-and-playable, they should implement the necessary logic themselves, and dependent
    SimProcedures should invoke a method by the same name as theirs (prepended with an underscore) upon the heap plugin.
    Depending on the heap implementation, if the method is not supported, an error should be raised.

    Out of consideration for the original way the heap was handled, this plugin implements functionality for all
    relevant SimProcedures (even those that would not normally be supported together in a single heap implementation).

    :ivar heap_location: the address of the top of the heap, bounding the allocations made starting from `heap_base`
    """

    def __init__(self, heap_base=None, heap_size=None):
        super(SimHeapBrk, self).__init__(heap_base, heap_size)
        self.heap_location = self.heap_base

    @SimStatePlugin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.heap_location = self.heap_location
        return o

    def allocate(self, sim_size):
        """
        The actual allocation primitive for this heap implementation. Increases the position of the break to allocate
        space. Has no guards against the heap growing too large.

        :param sim_size: a size specifying how much to increase the break pointer by
        :returns: a pointer to the previous break position, above which there is now allocated space
        """
        size = self._conc_alloc_size(sim_size)
        while size % 16 != 0:
            size += 1
        addr = self.state.heap.heap_location
        self.state.heap.heap_location += size
        l.debug("Allocating %d bytes at address %#08x", size, addr)
        return addr

    def release(self, sim_size):
        """
        The memory release primitive for this heap implementation. Decreases the position of the break to deallocate
        space. Guards against releasing beyond the initial heap base.

        :param sim_size: a size specifying how much to decrease the break pointer by (may be symbolic or not)
        """
        requested = self._conc_alloc_size(sim_size)
        used = self.heap_location - self.heap_base
        released = requested if requested <= used else used
        self.heap_location -= released
        l.debug("Releasing %d bytes from the heap (%d bytes were requested to be released)", released, requested)

    def _malloc(self, sim_size):
        return self.allocate(sim_size)

    def _free(self, ptr):  #pylint:disable=unused-argument
        return self.state.solver.Unconstrained('free', self.state.arch.bits)

    def _calloc(self, sim_nmemb, sim_size):
        plugin = self.state.get_plugin('libc')

        if self.state.solver.symbolic(sim_nmemb):
            # TODO: find a better way
            nmemb = self.state.solver.max_int(sim_nmemb)
        else:
            nmemb = self.state.solver.eval(sim_nmemb)

        if self.state.solver.symbolic(sim_size):
            # TODO: find a better way
            size = self.state.solver.max_int(sim_size)
        else:
            size = self.state.solver.eval(sim_size)

        final_size = size * nmemb

        if self.state.solver.symbolic(sim_nmemb) or self.state.solver.symbolic(sim_size):
            if final_size > plugin.max_variable_size:
                final_size = plugin.max_variable_size

        addr = self.state.heap.allocate(final_size)
        v = self.state.solver.BVV(0, final_size * 8)
        self.state.memory.store(addr, v)
        return addr

    def _realloc(self, ptr, size):
        if size.symbolic:
            try:
                size_int = self.state.solver.max(size, extra_constraints=(size < self.state.libc.max_variable_size,))
            except SimSolverError:
                size_int = self.state.solver.min(size)
            self.state.add_constraints(size_int == size)
        else:
            size_int = self.state.solver.eval(size)

        addr = self.state.heap.allocate(size_int)

        if self.state.solver.eval(ptr) != 0:
            v = self.state.memory.load(ptr, size_int)
            self.state.memory.store(addr, v)

        return addr

    def _combine(self, others):
        new_heap_location = max(o.heap_location for o in others)
        if self.heap_location != new_heap_location:
            self.heap_location = new_heap_location
            return True
        else:
            return False

    def merge(self, others, merge_conditions, common_ancestor=None):  #pylint:disable=unused-argument
        return self._combine(others)

    def widen(self, others):
        return self._combine(others)

from angr.sim_state import SimState
SimState.register_default('heap', SimHeapBrk)
