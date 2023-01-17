from . import SimHeapLibc
from .utils import concretize
from ...errors import SimHeapError

import logging

l = logging.getLogger("angr.state_plugins.heap.heap_freelist")


class Chunk:
    """
    The sort of chunk as would typically be found in a freelist-style heap implementation. Provides a representation of
    a chunk via a view into the memory plugin. Chunks may be adjacent, in different senses, to as many as four other
    chunks. For any given chunk, two of these chunks are adjacent to it in memory, and are referred to as the "previous"
    and "next" chunks throughout this implementation. For any given free chunk, there may also be two significant chunks
    that are adjacent to it in some linked list of free chunks. These chunks are referred to the "backward" and "foward"
    chunks relative to the chunk in question.

    :ivar base: the location of the base of the chunk in memory
    :ivar state: the program state that the chunk is resident in
    """

    def __init__(self, base, sim_state):
        self.state = sim_state

        def sym_chunk_handler(chunk):
            l.warning("A pointer to a chunk is symbolic; maximizing it")
            return self.state.solver.max_int(chunk)

        self.base = concretize(base, self.state.solver, sym_chunk_handler)

    def get_size(self):
        """
        Returns the actual size of a chunk (as opposed to the entire size field, which may include some flags).
        """
        raise NotImplementedError(f"{self.get_size.__func__.__name__} not implemented for {self.__class__.__name__}")

    def get_data_size(self):
        """
        Returns the size of the data portion of a chunk.
        """
        raise NotImplementedError(f"{self.get_size.__func__.__name__} not implemented for {self.__class__.__name__}")

    def set_size(self, size):
        """
        Sets the size of the chunk, preserving any flags.
        """
        raise NotImplementedError(f"{self.set_size.__func__.__name__} not implemented for {self.__class__.__name__}")

    def data_ptr(self):
        """
        Returns the address of the payload of the chunk.
        """
        raise NotImplementedError(f"{self.data_ptr.__func__.__name__} not implemented for {self.__class__.__name__}")

    def is_free(self):
        """
        Returns a concrete determination as to whether the chunk is free.
        """
        raise NotImplementedError(f"{self.is_free.__func__.__name__} not implemented for {self.__class__.__name__}")

    def next_chunk(self):
        """
        Returns the chunk immediately following (and adjacent to) this one.
        """
        raise NotImplementedError(f"{self.next_chunk.__func__.__name__} not implemented for {self.__class__.__name__}")

    def prev_chunk(self):
        """
        Returns the chunk immediately prior (and adjacent) to this one.
        """
        raise NotImplementedError(f"{self.prev_chunk.__func__.__name__} not implemented for {self.__class__.__name__}")

    def fwd_chunk(self):
        """
        Returns the chunk following this chunk in the list of free chunks.
        """
        raise NotImplementedError(f"{self.fwd_chunk.__func__.__name__} not implemented for {self.__class__.__name__}")

    def set_fwd_chunk(self, fwd):
        """
        Sets the chunk following this chunk in the list of free chunks.

        :param fwd: the chunk to follow this chunk in the list of free chunks
        """
        raise NotImplementedError(
            f"{self.set_fwd_chunk.__func__.__name__} not implemented for {self.__class__.__name__}"
        )

    def bck_chunk(self):
        """
        Returns the chunk backward from this chunk in the list of free chunks.
        """
        raise NotImplementedError(f"{self.bck_chunk.__func__.__name__} not implemented for {self.__class__.__name__}")

    def set_bck_chunk(self, bck):
        """
        Sets the chunk backward from this chunk in the list of free chunks.

        :param bck: the chunk to precede this chunk in the list of free chunks
        """
        raise NotImplementedError(
            f"{self.set_bck_chunk.__func__.__name__} not implemented for {self.__class__.__name__}"
        )

    def _compare(self, other, comparison):
        if self.state is other.state:
            return comparison
        else:
            raise SimHeapError("Chunks must originate from the same simulation state to be compared!")

    def __lt__(self, other):
        """
        Compares the base of this chunk with another chunk.
        """
        return self._compare(other, self.base < other.base)

    def __le__(self, other):
        """
        Compares the base of this chunk with another chunk.
        """
        return self._compare(other, self.base <= other.base)

    def __eq__(self, other):
        """
        Compares the base of this chunk with another chunk.
        """
        return self._compare(other, self.base == other.base)

    def __ne__(self, other):
        """
        Compares the base of this chunk with another chunk.
        """
        return self._compare(other, self.base != other.base)

    def __gt__(self, other):
        """
        Compares the base of this chunk with another chunk.
        """
        return self._compare(other, self.base > other.base)

    def __ge__(self, other):
        """
        Compares the base of this chunk with another chunk.
        """
        return self._compare(other, self.base >= other.base)

    def __repr__(self):
        return "<{} ({} @ 0x{:x})>".format(self.__class__.__name__, "free" if self.is_free() else "used", self.base)


class SimHeapFreelist(SimHeapLibc):
    """
    A freelist-style heap implementation. Distinguishing features of such heaps include chunks containing heap
    metadata in addition to user data and at least (but often more than) one linked list of free chunks.
    """

    def __iter__(self):
        return self.chunks()

    def chunks(self):
        """
        Returns an iterator over all the chunks in the heap.
        """
        raise NotImplementedError(f"{self.chunks.__func__.__name__} not implemented for {self.__class__.__name__}")

    def allocated_chunks(self):
        """
        Returns an iterator over all the allocated chunks in the heap.
        """
        raise NotImplementedError(
            f"{self.allocated_chunks.__func__.__name__} not implemented for {self.__class__.__name__}"
        )

    def free_chunks(self):
        """
        Returns an iterator over all the free chunks in the heap.
        """
        raise NotImplementedError(f"{self.free_chunks.__func__.__name__} not implemented for {self.__class__.__name__}")

    def chunk_from_mem(self, ptr):
        """
        Given a pointer to a user payload, return the chunk associated with that payload.

        :param ptr: a pointer to the base of a user payload in the heap
        :returns: the associated heap chunk
        """
        raise NotImplementedError(
            f"{self.chunk_from_mem.__func__.__name__} not implemented for {self.__class__.__name__}"
        )

    def print_heap_state(self):
        print("|-------------------------------|")
        print("|--------- HEAP CHUNKS ---------|")
        for ck in self.chunks():
            print("│ " + str(ck) + " │")
        print("|--------- USED CHUNKS ---------|")
        for ck in self.allocated_chunks():
            print("│ " + str(ck) + " │")
        print("|--------- FREE CHUNKS ---------|")
        for ck in self.free_chunks():
            print("│ " + str(ck) + " │")
        print("|-------------------------------|")

    def print_all_chunks(self):
        print("|-------------------------------|")
        print("|--------- HEAP CHUNKS ---------|")
        for ck in self.chunks():
            print("│ " + str(ck) + " │")
        print("|-------------------------------|")
