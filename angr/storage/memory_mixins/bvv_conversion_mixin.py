import logging
import claripy

from angr.storage.memory_mixins import MemoryMixin

l = logging.getLogger(__name__)


class DataNormalizationMixin(MemoryMixin):
    """
    Normalizes the data field for a store and the fallback field for a load to be BVs.
    """
    def store(self, addr, data, size=None, **kwargs):
        data_bv = self._convert_to_ast(data, size, self.state.arch.byte_width)

        # zero extend if size is greater than len(data_e)
        # TODO move this to the register resolver
        #bit_width = size*self.state.arch.byte_width if isinstance(size, int) else self.state.arch.bits
        #if size is not None and self.category == 'reg' and len(data_bv) < bit_width:
        #    data_bv = data_bv.zero_extend(bit_width - len(data_bv))

        if len(data_bv) % self.state.arch.byte_width != 0:
            raise SimMemoryError("Attempting to store non-byte data to memory")

        super().store(addr, data_bv, size=size, **kwargs)

    def load(self, addr, size=None, fallback=None, **kwargs):
        fallback_bv = self._convert_to_ast(fallback, size, self.state.arch.byte_width) if fallback is not None else None
        return super().load(addr, size=size, fallback=fallback_bv, **kwargs)

    def _convert_to_ast(self, thing, size, byte_width):
        """
        :param thing:       The thing to convert to an AST
        :param size:        The size of the thing in bytes
        :param byte_width:  The size of a byte in bits
        """
        if type(thing) is claripy.ast.BV:
            return thing

        if type(size) is int:
            bits = size * byte_width
        elif getattr(size, 'op', None) == 'BVV':
            bits = size.args[0] * byte_width
        else:
            bits = None

        if isinstance(thing, str):
            l.warning("Encoding unicode string for memory as utf-8. Did you mean to use a bytestring?")
            thing = thing.encode('utf-8')
        if type(thing) in (bytes, bytearray, memoryview):
            return claripy.BVV(thing)
        elif type(thing) is int:
            if bits is None:
                l.warning("Unknown size for memory data %#x. Default to arch.bits.", thing)
                bits = self.state.arch.bits
            return claripy.BVV(thing, bits)
        elif type(thing) is float:
            if bits == 32:
                return claripy.FPV(thing, claripy.FSORT_FLOAT).raw_to_bv()
            elif bits == 64:
                return claripy.FPV(thing, claripy.FSORT_DOUBLE).raw_to_bv()
            else:
                raise TypeError("Passed float size which is not a float or a double", size)
        else:
            try:
                raw_to_bv = thing.raw_to_bv
            except AttributeError:
                raise TypeError("Bad value passed to memory", thing) from None
            else:
                return raw_to_bv()

from ...errors import SimMemoryError
