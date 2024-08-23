from __future__ import annotations
from . import SimHeapBase


class SimHeapLibc(SimHeapBase):
    """
    A class of heap that implements the major libc heap management functions.
    """

    def malloc(self, sim_size):
        """
        A somewhat faithful implementation of libc `malloc`.

        :param sim_size: the amount of memory (in bytes) to be allocated
        :returns:        the address of the allocation, or a NULL pointer if the allocation failed
        """
        raise NotImplementedError(f"{self.malloc.__func__.__name__} not implemented for {self.__class__.__name__}")

    def free(self, ptr):  # pylint:disable=unused-argument
        """
        A somewhat faithful implementation of libc `free`.

        :param ptr: the location in memory to be freed
        """
        raise NotImplementedError(f"{self.free.__func__.__name__} not implemented for {self.__class__.__name__}")

    def calloc(self, sim_nmemb, sim_size):
        """
        A somewhat faithful implementation of libc `calloc`.

        :param     sim_nmemb: the number of elements to allocated
        :param     sim_size: the size of each element (in bytes)
        :returns:  the address of the allocation, or a NULL pointer if the allocation failed
        """
        raise NotImplementedError(f"{self.calloc.__func__.__name__} not implemented for {self.__class__.__name__}")

    def realloc(self, ptr, size):
        """
        A somewhat faithful implementation of libc `realloc`.

        :param ptr:  the location in memory to be reallocated
        :param size: the new size desired for the allocation
        :returns:    the address of the allocation, or a NULL pointer if the allocation was freed or if no new
                     allocation was made
        """
        raise NotImplementedError(f"{self.realloc.__func__.__name__} not implemented for {self.__class__.__name__}")
