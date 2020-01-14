import logging
import claripy

from angr.storage.memory_mixins import MemoryMixin

l = logging.getLogger(__name__)

class BVVConversionMixin(MemoryMixin):
    def store(self, addr, data, size=None, **kwargs):
        data_bv = self._convert_to_ast(data, size, self.state.arch.byte_width)

        # zero extend if size is greater than len(data_e)
        bit_width = size*self.state.arch.byte_width if isinstance(size, int) else self.state.arch.bits
        if size is not None and self.category == 'reg' and len(data_bv) < bit_width:
            data_bv = data_bv.zero_extend(bit_width - len(data_bv))

        size_bv = self._convert_to_ast(size, None, self.state.arch.byte_width, allow_fp=False)

        if len(data_bv) % self.state.arch.byte_width != 0:
            raise SimMemoryError("Attempting to store non-byte data to memory")
        if size_bv.op == 'BVV' and len(data_bv) < size_bv.args[0]*self.state.arch.byte_width:
            raise SimMemoryError("Provided data is too short for this memory store")

        return self.store(addr, data_bv, size=size_bv, **kwargs)

    def load(self, addr, size=None, fallback=None, **kwargs):
        size = self._convert_to_ast(size, None, self.state.arch.byte_width, allow_fp=False)
        fallback = self._convert_to_ast(fallback, size, self.state.arch.byte_width) if fallback is not None else None
        return super().load(addr, size=size, fallback=fallback, **kwargs)

    def _convert_to_ast(self, thing, size, byte_width, allow_fp=True):
        """
        :param thing:       The thing to convert to an AST
        :param size:        The size of the thing in bytes
        :param byte_width:  The size of a byte in bits
        """
        if size is None:
            size = self.state.arch.bits
        elif type(size) is int:
            size = size * byte_width
        else:
            raise TypeError("Bad size passed to memory", size)

        if isinstance(thing, str):
            l.warning("Encoding unicode string for memory as utf-8. Did you mean to use a bytestring?")
            thing = thing.encode()
        if type(thing) is bytes:
            # Convert the string into a BVV, *regardless of endness*
            bits = len(thing) * byte_width
            return claripy.BVV(thing, bits)
        elif type(thing) is int:
            return claripy.BVV(thing, size)
        elif type(thing) is float and allow_fp:
            if size == 32:
                return claripy.FPV(thing, claripy.FSORT_FLOAT).raw_to_bv()
            elif size == 64:
                return claripy.FPV(thing, claripy.FSORT_DOUBLE).raw_to_bv()
            else:
                return TypeError("Passed float size which is not a float or a double")
        else:
            try:
                raw_to_bv = thing.raw_to_bv
            except AttributeError:
                raise TypeError("Bad value passed to memory", thing) from None
            else:
                return raw_to_bv()

from ...errors import SimMemoryError
