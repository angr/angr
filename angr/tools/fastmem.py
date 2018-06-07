import struct
import cffi

from angr.errors import AngrError
from .tool import Tool


class FastMemory(Tool):
    """
    Provides means for fast memory loading of static content from static regions.
    Extracted from CFGFast analysis.
    """

    def __init__(self):
        super(FastMemory, self).__init__()

        self._ffi = cffi.FFI()
        self._pointer_size = self.arch.bits // 8

    def __getstate__(self):
        s = super(FastMemory, self).__getstate__()
        return s, self.project, self._pointer_size

    def __setstate__(self, s):
        s, self.project, self._pointer_size = s
        self._ffi = cffi.FFI()
        super(FastMemory, self).__setstate__(s)

    @property
    def memory(self):
        return self.project.loader.memory

    @property
    def arch(self):
        return self.project.arch

    @property
    def pointer_size(self):
        return self._pointer_size

    @pointer_size.setter
    def pointer_size(self, value):
        self._pointer_size = value

    def load_byte(self, addr):
        """
        Perform a fast memory loading of a byte.

        :param int addr: Address to read from.
        :return:         A char or None if the address does not exist.
        :rtype:          str or None
        """
        return self.load_bytes(addr, 1)

    def load_bytes(self, addr, length):
        """
        Perform a fast memory loading of a byte.

        :param int addr: Address to read from.
        :param int length: Size of the string to load.
        :return:         A string or None if the address does not exist.
        :rtype:          str or None
        """
        buf, size = self._load(addr)
        if buf is None:
            return None
        if size == 0:
            return None

        # Make sure it does not go over-bound
        length = min(length, size)

        char_str = self._ffi.unpack(self._ffi.cast('char*', buf), length)  # type: str
        return char_str

    def load_pointer(self, addr):
        """
        Perform a fast memory loading of a pointer.

        :param int addr: Address to read from.
        :return:         A pointer or None if the address does not exist.
        :rtype:          int
        """
        pointer_size = self.arch.bits / 8
        buf, size = self._load(addr)
        if buf is None:
            return None

        if self.arch.memory_endness == 'Iend_LE':
            fmt = "<"
        else:
            fmt = ">"

        if pointer_size == 8:
            if size >= 8:
                fmt += "Q"
            else:
                # Insufficient bytes left in the current block for making an 8-byte pointer
                return None
        elif pointer_size == 4:
            if size >= 4:
                fmt += "I"
            else:
                # Insufficient bytes left in the current block for making a 4-byte pointer.
                return None
        else:
            raise AngrError("Pointer size of %d is not supported" % pointer_size)

        ptr_str = self._ffi.unpack(self._ffi.cast('char*', buf), pointer_size)
        ptr = struct.unpack(fmt, ptr_str)[0]  # type:int
        return ptr

    def _load(self, addr):
        """
        Perform a fast memory loading of static content from static regions, a.k.a regions that are mapped to the
        memory by the loader.

        :param int addr: Address to read from.
        :return: The data, or None if the address does not exist.
        :rtype: cffi.CData
        """
        try:
            buff, size = self.memory.read_bytes_c(addr)
            return buff, size
        except KeyError:
            return None, None
