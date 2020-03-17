from ..plugin import SimStatePlugin
from .heap_freelist import SimHeapFreelist, Chunk
from .utils import concretize

from ...errors import SimHeapError, SimMergeError, SimSolverError


import logging

l = logging.getLogger("angr.state_plugins.heap.heap_ptmalloc")
sml = logging.getLogger('angr.state_plugins.symbolic_memory')

CHUNK_FLAGS_MASK = 0x07
CHUNK_P_MASK = 0x01

# These are included as sometimes the heap will touch uninitialized locations, which normally causes a warning
def silence_logger():
    level = sml.getEffectiveLevel()
    sml.setLevel('ERROR')
    return level

def unsilence_logger(level):
    sml.setLevel(level)

class PTChunk(Chunk):
    """
    A chunk, inspired by the implementation of chunks in ptmalloc. Provides a representation of a chunk via a view into
    the memory plugin. For the chunk definitions and docs that this was loosely based off of, see glibc malloc/malloc.c,
    line 1033, as of commit 5a580643111ef6081be7b4c7bd1997a5447c903f. Alternatively, take the following link.
    https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=67cdfd0ad2f003964cd0f7dfe3bcd85ca98528a7;hb=5a580643111ef6081be7b4c7bd1997a5447c903f#l1033

    :ivar base: the location of the base of the chunk in memory
    :ivar state: the program state that the chunk is resident in
    :ivar heap: the heap plugin that the chunk is managed by
    """

    def __init__(self, base, sim_state, heap=None):
        super(PTChunk, self).__init__(base, sim_state)

        # This is necessary since the heap can't always be referenced through the state, e.g. during heap initialization
        self.heap = self.state.heap if heap is None else heap

        # Size in bytes of the type used to store a piece of metadata
        self._chunk_size_t_size = self.heap._chunk_size_t_size
        self._chunk_min_size = self.heap._chunk_min_size
        self._chunk_align_mask = self.heap._chunk_align_mask

    def get_size(self):
        return self.state.memory.load(self.base + self._chunk_size_t_size, self._chunk_size_t_size) & ~CHUNK_FLAGS_MASK

    def get_data_size(self):
        chunk_size = self.get_size()
        if self.is_free():
            return chunk_size - 4 * self._chunk_size_t_size
        else:
            return chunk_size - 2 * self._chunk_size_t_size

    def _set_leading_size(self, size):
        level = silence_logger()
        chunk_flags = self.state.memory.load(self.base + self._chunk_size_t_size, self._chunk_size_t_size) \
                      & CHUNK_FLAGS_MASK
        unsilence_logger(level)
        self.state.memory.store(self.base + self._chunk_size_t_size, size | chunk_flags)

    def _set_trailing_size(self, size):
        if self.is_free():
            next_chunk = self.next_chunk()
            if next_chunk is not None:
                self.state.memory.store(next_chunk.base, size)

    def set_size(self, size, is_free=None):  #pylint:disable=arguments-differ
        """
        Use this to set the size on a chunk. When the chunk is new (such as when a free chunk is shrunk to form an
        allocated chunk and a remainder free chunk) it is recommended that the is_free hint be used since setting the
        size depends on the chunk's freeness, and vice versa.

        :param size: size of the chunk
        :param is_free: boolean indicating the chunk's freeness
        """
        self._set_leading_size(size)
        next_chunk = self.next_chunk()
        if is_free is not None:
            if next_chunk is not None:
                next_chunk.set_prev_freeness(is_free)
            else:
                self.heap._set_final_freeness(is_free)
        if is_free is not None and is_free or self.is_free():
            if next_chunk is not None:
                self.state.memory.store(next_chunk.base, size)

    def set_prev_freeness(self, is_free):
        """
        Sets (or unsets) the flag controlling whether the previous chunk is free.

        :param is_free: if True, sets the previous chunk to be free; if False, sets it to be allocated
        """
        level = silence_logger()
        size_field = self.state.memory.load(self.base + self._chunk_size_t_size, self._chunk_size_t_size)
        unsilence_logger(level)
        if is_free:
            self.state.memory.store(self.base + self._chunk_size_t_size, size_field & ~CHUNK_P_MASK)
        else:
            self.state.memory.store(self.base + self._chunk_size_t_size, size_field | CHUNK_P_MASK)

    def is_prev_free(self):
        """
        Returns a concrete state of the flag indicating whether the previous chunk is free or not. Issues a warning if
        that flag is symbolic and has multiple solutions, and then assumes that the previous chunk is free.

        :returns: True if the previous chunk is free; False otherwise
        """
        flag = self.state.memory.load(self.base + self._chunk_size_t_size, self._chunk_size_t_size) & CHUNK_P_MASK

        def sym_flag_handler(flag):
            l.warning("A chunk's P flag is symbolic; assuming it is not set")
            return self.state.solver.min_int(flag)

        flag = concretize(flag, self.state.solver, sym_flag_handler)
        return False if flag else True

    def prev_size(self):
        """
        Returns the size of the previous chunk, masking off what would be the flag bits if it were in the actual size
        field. Performs NO CHECKING to determine whether the previous chunk size is valid (for example, when the
        previous chunk is not free, its size cannot be determined).
        """
        return self.state.memory.load(self.base, self._chunk_size_t_size) & ~CHUNK_FLAGS_MASK

    def is_free(self):
        next_chunk = self.next_chunk()
        if next_chunk is not None:
            return next_chunk.is_prev_free()
        else:
            flag = self.state.memory.load(self.heap.heap_base
                                          + self.heap.heap_size
                                          - self._chunk_size_t_size
                                          , self._chunk_size_t_size) \
                   & CHUNK_P_MASK

            def sym_flag_handler(flag):
                l.warning("The final P flag is symbolic; assuming it is not set")
                return self.state.solver.min_int(flag)

            flag = concretize(flag, self.state.solver, sym_flag_handler)
            return False if flag else True

    def data_ptr(self):
        return self.base + (2 * self._chunk_size_t_size)

    def next_chunk(self):
        """
        Returns the chunk immediately following (and adjacent to) this one, if it exists.

        :returns: The following chunk, or None if applicable
        """

        def sym_base_handler(base):
            l.warning("A computed chunk base is symbolic; maximizing it")
            return self.state.solver.max_int(base)

        base = concretize(self.base + self.get_size(), self.state.solver, sym_base_handler)
        if base >= self.heap.heap_base + self.heap.heap_size - 2 * self._chunk_size_t_size:
            return None
        else:
            return PTChunk(base, self.state)

    def prev_chunk(self):
        """
        Returns the chunk immediately prior (and adjacent) to this one, if that chunk is free. If the prior chunk is not
        free, then its base cannot be located and this method raises an error.

        :returns: If possible, the previous chunk; otherwise, raises an error
        """
        if self.is_prev_free():
            return PTChunk(self.base - self.prev_size(), self.state)
        else:
            raise SimHeapError("Attempted to access the previous chunk, but it was not free")

    def fwd_chunk(self):
        """
        Returns the chunk following this chunk in the list of free chunks. If this chunk is not free, then it resides in
        no such list and this method raises an error.

        :returns: If possible, the forward chunk; otherwise, raises an error
        """
        if self.is_free():
            base = self.state.memory.load(self.base + 2 * self._chunk_size_t_size, self._chunk_size_t_size, endness=self.state.arch.memory_endness)
            return PTChunk(base, self.state)
        else:
            raise SimHeapError("Attempted to access the forward chunk of an allocated chunk")

    def set_fwd_chunk(self, fwd):
        self.state.memory.store(self.base + 2 * self._chunk_size_t_size, fwd.base, endness=self.state.arch.memory_endness)

    def bck_chunk(self):
        """
        Returns the chunk backward from this chunk in the list of free chunks. If this chunk is not free, then it
        resides in no such list and this method raises an error.

        :returns: If possible, the backward chunk; otherwise, raises an error
        """
        if self.is_free():
            base = self.state.memory.load(self.base + 3 * self._chunk_size_t_size, self._chunk_size_t_size, endness=self.state.arch.memory_endness)
            return PTChunk(base, self.state)
        else:
            raise SimHeapError("Attempted to access the backward chunk of an allocated chunk")

    def set_bck_chunk(self, bck):
        self.state.memory.store(self.base + 3 * self._chunk_size_t_size, bck.base, endness=self.state.arch.memory_endness)

class PTChunkIterator:
    def __init__(self, chunk, cond=lambda chunk: True):
        self.chunk = chunk
        self.cond = cond

    def __iter__(self):
        return self

    def __next__(self):
        if self.chunk is None:
            raise StopIteration

        if self.cond(self.chunk):
            ret = self.chunk
            self.chunk = self.chunk.next_chunk()
        else:
            while self.chunk is not None and not self.cond(self.chunk):
                self.chunk = self.chunk.next_chunk()
            if self.chunk is None:
                raise StopIteration
            else:
                ret = self.chunk
                self.chunk = self.chunk.next_chunk()

        return ret

class SimHeapPTMalloc(SimHeapFreelist):
    """
    A freelist-style heap implementation inspired by ptmalloc. The chunks used by this heap contain heap metadata in
    addition to user data. While the real-world ptmalloc is implemented using multiple lists of free chunks
    (corresponding to their different sizes), this more basic model uses a single list of chunks and searches for free
    chunks using a first-fit algorithm.

    **NOTE:** The plugin must be registered using ``register_plugin`` with name ``heap`` in order to function properly.

    :ivar heap_base: the address of the base of the heap in memory
    :ivar heap_size: the total size of the main memory region managed by the heap in memory
    :ivar mmap_base: the address of the region from which large mmap allocations will be made
    :ivar free_head_chunk: the head of the linked list of free chunks in the heap
    """

    def __init__(self, heap_base=None, heap_size=None):
        super(SimHeapPTMalloc, self).__init__(heap_base, heap_size)

        # All of these depend on the state and so are initialized in init_state
        self._free_head_chunk_exists = True  # Only used during plugin copy due to the dependency on the memory plugin
        self._free_head_chunk_init_base = None  # Same as above
        self._chunk_size_t_size = None  # Size (bytes) of the type used to store a piece of metadata
        self._chunk_min_size = None  # Based on needed fields for any chunk
        self.free_head_chunk = None
        self._initialized = False

    def chunks(self):
        return PTChunkIterator(PTChunk(self.heap_base, self.state))

    def allocated_chunks(self):
        return PTChunkIterator(PTChunk(self.heap_base, self.state), lambda chunk: not chunk.is_free())

    def free_chunks(self):
        return PTChunkIterator(PTChunk(self.heap_base, self.state), lambda chunk: chunk.is_free())

    def chunk_from_mem(self, ptr):
        """
        Given a pointer to a user payload, return the base of the chunk associated with that payload (i.e. the chunk
        pointer). Returns None if ptr is null.

        :param ptr: a pointer to the base of a user payload in the heap
        :returns: a pointer to the base of the associated heap chunk, or None if ptr is null
        """
        if self.state.solver.symbolic(ptr):
            try:
                ptr = self.state.solver.eval_one(ptr)
            except SimSolverError:
                l.warning("A pointer to a chunk is symbolic; maximizing it")
                ptr = self.state.solver.max_int(ptr)
        else:
            ptr = self.state.solver.eval(ptr)
        return PTChunk(ptr - (2 * self._chunk_size_t_size), self.state) if ptr != 0 else None

    def _find_bck(self, chunk):
        """
        Simply finds the free chunk that would be the backwards chunk relative to the chunk at ptr. Hence, the free head
        and all other metadata are unaltered by this function.
        """
        cur = self.free_head_chunk
        if cur is None:
            return None
        fwd = cur.fwd_chunk()
        if cur == fwd:
            return cur
        # At this point there should be at least two free chunks in the heap
        if cur < chunk:
            while cur < fwd < chunk:
                cur = fwd
                fwd = cur.fwd_chunk()
            return cur
        else:
            while fwd != self.free_head_chunk:
                cur = fwd
                fwd = cur.fwd_chunk()
            return cur

    def _set_final_freeness(self, flag):
        """
        Sets the freedom of the final chunk. Since no proper chunk follows the final chunk, the heap itself manages
        this. Nonetheless, for now it is implemented as if an additional chunk followed the final chunk.
        """
        if flag:
            self.state.memory.store(self.heap_base + self.heap_size - self._chunk_size_t_size, ~CHUNK_P_MASK)
        else:
            self.state.memory.store(self.heap_base + self.heap_size - self._chunk_size_t_size, CHUNK_P_MASK)

    def _make_chunk_size(self, req_size):
        """
        Takes an allocation size as requested by the user and modifies it to be a suitable chunk size.
        """
        size = req_size
        size += 2 * self._chunk_size_t_size  # Two size fields
        size = self._chunk_min_size if size < self._chunk_min_size else size
        if size & self._chunk_align_mask:                                         # If the chunk would not be aligned
            size = (size & ~self._chunk_align_mask) + self._chunk_align_mask + 1  # Fix it
        return size

    def malloc(self, sim_size):
        size = self._conc_alloc_size(sim_size)
        req_size = size
        size = self._make_chunk_size(size)

        chunk = None  # This will be the resulting allocation
        free_chunk = self.free_head_chunk
        if free_chunk is None:
            l.warning("No free chunks available; heap space exhausted")
            return 0  # No free chunks available

        # This handler will be necessary as we'll be checking the size fields of many free chunks
        def sym_free_size_handler(size):
            l.warning("A free chunk's size field is symbolic; maximizing it")
            return self.state.solver.max_int(size)

        while chunk is None:
            free_size = free_chunk.get_size()
            free_size = concretize(free_size, self.state.solver, sym_free_size_handler)
            if free_size < size:
                # Chunk is too small to be used; move to the next or fail
                fwd = free_chunk.fwd_chunk()
                if fwd <= free_chunk:
                    l.debug("No free chunks of sufficient size available")
                    return 0
                else:
                    free_chunk = fwd
            elif free_size > size and free_size - size >= self._chunk_min_size:
                # Chunk may be too large but we'll use it anyway
                chunk = free_chunk
                bck = free_chunk.bck_chunk()  # Store these now as we'll have to remove this chunk from the list
                fwd = free_chunk.fwd_chunk()

                rem_chunk = PTChunk(chunk.base + size, chunk.state)  # The "remainder" chunk is the unused portion after
                rem_chunk.set_size(free_size - size, True)           # the allocation is made. Since it follows the used
                rem_chunk.set_prev_freeness(False)                   # portion, we can set the used chunk as not free.
                if free_chunk == self.free_head_chunk:
                    self.free_head_chunk = rem_chunk  # If the used chunk had been the head, now the remainder is
                chunk.set_size(size)
                if free_chunk == bck and free_chunk == fwd:  # If the free chunk had been the only free chunk, then the
                    rem_chunk.set_bck_chunk(rem_chunk)       # remainder chunk is now the only free chunk
                    rem_chunk.set_fwd_chunk(rem_chunk)
                else:
                    rem_chunk.set_bck_chunk(bck)             # Otherwise there was at least one other chunk, and the
                    rem_chunk.set_fwd_chunk(fwd)             # remainder chunk may safely replace the original in the
                    bck.set_fwd_chunk(rem_chunk)             # list
                    fwd.set_bck_chunk(rem_chunk)
            else:
                # Chunk is a perfect fit, or the remainder would be too small to split off as a free chunk
                chunk = free_chunk
                fwd = free_chunk.fwd_chunk()  # Once again we store these in advance
                bck = free_chunk.bck_chunk()
                if bck == fwd and free_chunk == fwd:  # Last chunk being used up
                    self.free_head_chunk = None
                else:
                    if free_chunk == self.free_head_chunk:
                        self.free_head_chunk = fwd
                    bck.set_fwd_chunk(fwd)  # We can safely remove the chunk from the list
                    fwd.set_bck_chunk(bck)
                next_chunk = chunk.next_chunk()          # Now we set the new chunk to be allocated, using a different
                if next_chunk is not None:               # approach depending on whether the chunk was the last in the
                    next_chunk.set_prev_freeness(False)  # heap or not
                else:
                    self._set_final_freeness(False)

        addr = chunk.data_ptr()
        l.debug("Requested: %4d; Allocated: %4d; Returned: %#08x; Chunk: %#08x", req_size, size, addr, chunk.base)
        return addr

    def free(self, ptr):
        # In the following, "next" and "previous" (and their abbreviations) refer to the adjacent chunks in memory,
        # while forward and backward (and their abbreviations) refer to the adjacent chunks in the list of free chunks
        req = ptr
        chunk = self.chunk_from_mem(ptr)
        if chunk is None:
            return
        size = chunk.get_size()

        p_in_use = False if chunk.is_prev_free() else True
        n_ptr = chunk.next_chunk()
        n_in_use = False if n_ptr is not None and n_ptr.is_free() else True  # Next is taken to be in use if it doesn't
        if p_in_use and n_in_use:                                            # exist
            # When both adjacent chunks are in use, no merging will be
            # necessary between the freed chunk and another free chunk
            if n_ptr is not None:
                n_ptr.set_prev_freeness(True)  # Set the chunk to be free
            else:
                self._set_final_freeness(True)
            chunk.set_size(size)           # Reset the chunk's size to account for the trailing size field
            bck = self._find_bck(chunk)    # Scan the free list to determine where to insert the newly freed chunk
            if bck is None:
                # There was no other chunk in the free list
                self.free_head_chunk = chunk
                bck = chunk
                fwd = chunk
            else:
                # Insert the chunk after the bck chunk that was found
                fwd = bck.fwd_chunk()
                bck.set_fwd_chunk(chunk)
                fwd.set_bck_chunk(chunk)
            chunk.set_bck_chunk(bck)
            chunk.set_fwd_chunk(fwd)
            if chunk < self.free_head_chunk:
                self.free_head_chunk = chunk
        elif not p_in_use and not n_in_use:
            # If both the adjacent chunks are free, merging between all three will be needed
            p_ptr = chunk.prev_chunk()  # The previous chunk will be the base of the overall new chunk
            p_ptr.set_size(p_ptr.get_size() + size + n_ptr.get_size())
            n_fwd = n_ptr.fwd_chunk()   # The chunk forward from the chunk that's next after the freed chunk, which is
            p_ptr.set_fwd_chunk(n_fwd)  # needed since we're removing a free chunk (chunk.next_chunk()) from the linked
            n_fwd.set_bck_chunk(p_ptr)  # list
        else:
            # There are two remaining cases, but we handle them generically below by deciding on a base for a new chunk,
            # determining its size, and updating all metadata around it (even though sometimes it isn't necessary).
            if not p_in_use:
                base = chunk.prev_chunk()
                new_size = size + base.get_size()
                bck = base.bck_chunk()
                fwd = base.fwd_chunk()
            else:
                n_size = n_ptr.get_size()
                base = chunk
                new_size = size + n_size
                bck = n_ptr.bck_chunk()
                fwd = n_ptr.fwd_chunk()

                # In case the freed chunk preceded the free head
                if base < self.free_head_chunk:
                    self.free_head_chunk = base

                # In case the following chunk was the last free chunk, we can't use its links due to the merge
                if bck == fwd and bck == n_ptr:
                    bck = base
                    fwd = base
            base.set_size(new_size)
            base.set_bck_chunk(bck)
            base.set_fwd_chunk(fwd)
            bck.set_fwd_chunk(base)
            fwd.set_bck_chunk(base)
            new_next = base.next_chunk()
            if new_next is not None:
                new_next.set_prev_freeness(True)
            else:
                self._set_final_freeness(True)
            # FIXME: must set size twice so that once free, the trailing size field is updated; more elegant way?
            base.set_size(new_size)

        l.debug("Free request: %#08x; Freed chunk: %#08x", self.state.solver.eval(req),
                self.state.solver.eval(chunk.base))

    def calloc(self, sim_nmemb, sim_size):
        size = self._conc_alloc_size(sim_nmemb * sim_size)
        addr = self.malloc(size)
        if addr == 0:
            return 0
        if size != 0:
            z = self.state.solver.BVV(0, size * 8)
            self.state.memory.store(addr, z)
        return addr

    def realloc(self, ptr, size):
        chunk = self.chunk_from_mem(ptr)
        if chunk is None:  # ptr is null
            return self.malloc(size)
        size = self._conc_alloc_size(size)
        if size == 0:
            # assumes that REALLOC_ZERO_BYTES_FREES is set for ptmalloc
            self.free(ptr)
            return 0
        old_size = chunk.get_size()

        def sym_size_handler(sym_size):
            l.warning("An allocated chunk's size field is symbolic; maximizing it")
            return self.state.solver.max_int(sym_size)

        old_size = concretize(old_size, self.state.solver, sym_size_handler)
        new_size = self._make_chunk_size(size)

        if new_size > old_size:
            # If more space is needed, will have to reallocate
            # TODO: this could be made more complex to make better usage of remaining heap space when it runs out by
            # TODO: checking for smaller adjacent free chunks that could be amalgamated (rather than malloc, copy, free)
            new_data_ptr = self.malloc(size)  # Make the new allocation
            if new_data_ptr == 0:  # Check for failure
                return 0
            # Copy the old data over
            old_data_ptr = chunk.data_ptr()
            level = silence_logger()
            old_data = self.state.memory.load(old_data_ptr, size=old_size - 2 * self._chunk_size_t_size)
            unsilence_logger(level)
            self.state.memory.store(new_data_ptr, old_data)
            self.free(old_data_ptr)  # Free the old chunk
            return new_data_ptr
        elif new_size < old_size and old_size - new_size >= self._chunk_min_size:
            # Less space is needed, so just shrink the chunk and create a new free chunk from the freed space
            chunk.set_size(new_size, False)
            new_next_chunk = chunk.next_chunk()
            new_next_chunk.set_size(old_size - new_size, False)
            new_next_chunk.set_prev_freeness(False)
            self.free(new_next_chunk.data_ptr())
            return chunk.data_ptr()
        else:
            # No changes needed; we're already the right size
            return chunk.data_ptr()

    def _malloc(self, sim_size):
        return self.malloc(sim_size)

    def _free(self, ptr):
        return self.free(ptr)

    def _calloc(self, sim_nmemb, sim_size):
        return self.calloc(sim_nmemb, sim_size)

    def _realloc(self, ptr, size):
        return self.realloc(ptr, size)

    @SimStatePlugin.memo
    def copy(self, memo):# pylint: disable=unused-argument
        c = SimHeapPTMalloc(heap_base=self.heap_base, heap_size=self.heap_size)
        c.mmap_base = self.mmap_base
        c._free_head_chunk_exists = True if self.free_head_chunk is not None else False
        c._free_head_chunk_init_base = self.free_head_chunk.base if self.free_head_chunk is not None else None
        c._initialized = self._initialized
        return c

    def _combine(self, others):
        if any(o.heap_base != self.heap_base for o in others):
            raise SimMergeError("Cannot merge heaps with different bases")
        # When heaps become more dynamic, this next one can probably change
        if any(o.heap_size != self.heap_size for o in others):
            raise SimMergeError("Cannot merge heaps with different sizes")
        if any(o.free_head_chunk != self.free_head_chunk for o in others):
            raise SimMergeError("Cannot merge heaps with different freelist head chunks")
        if any(o.mmap_base != self.mmap_base for o in others):
            raise SimMergeError("Cannot merge heaps with different mmap bases")

        # These are definitely sanity checks
        if any(o._chunk_size_t_size != self._chunk_size_t_size for o in others):
            raise SimMergeError("Cannot merge heaps with different chunk size_t sizes")
        if any(o._chunk_min_size != self._chunk_min_size for o in others):
            raise SimMergeError("Cannot merge heaps with different minimum chunk sizes")
        if any(o._chunk_align_mask != self._chunk_align_mask for o in others):
            raise SimMergeError("Cannot merge heaps with different chunk alignments")

        return False

    def merge(self, others, merge_conditions, common_ancestor=None):  #pylint:disable=unused-argument
        return self._combine(others)

    def widen(self, others):
        return self._combine(others)

    def init_state(self):
        super(SimHeapPTMalloc, self).init_state()

        self._chunk_size_t_size = self.state.arch.bits // 8
        self._chunk_min_size = 4 * self._chunk_size_t_size
        self._chunk_align_mask = 2 * self._chunk_size_t_size - 1  #pylint:disable=attribute-defined-outside-init

        # TODO: where are bin metadata stored in reality?
        if self._free_head_chunk_exists and self._free_head_chunk_init_base is None:
            free_base = self.heap_base
            if self.heap_base & self._chunk_align_mask:
                free_base = (self.heap_base & ~self._chunk_align_mask) + self._chunk_align_mask + 1
            self.free_head_chunk = PTChunk(free_base, self.state, self)
        elif not self._free_head_chunk_exists:
            self.free_head_chunk = None
        else:
            self.free_head_chunk = PTChunk(self._free_head_chunk_init_base, self.state)

        # We reserve enough space at the top of the heap to simulate the presence of another chunk, for the purpose of
        # storing the usage information of the real final chunk
        if not self._initialized:
            self.state.memory.store(self.free_head_chunk.base + self._chunk_size_t_size
                                    , ((self.heap_size - 2 * self._chunk_size_t_size) & ~self._chunk_align_mask)
                                    | CHUNK_P_MASK)
            self._set_final_freeness(True)
            self.free_head_chunk.set_fwd_chunk(self.free_head_chunk)
            self.free_head_chunk.set_bck_chunk(self.free_head_chunk)
            self._initialized = True
