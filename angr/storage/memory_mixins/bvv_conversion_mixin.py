import logging

l = logging.getLogger(__name__)

class BVVConversionMixin:
    def store(self, addr, data, size=None, **kwargs):
        if isinstance(data, str):
            l.warning("Storing unicode string encoded as utf-8. Did you mean to use a bytestring?")
            data = data.encode()

        data_bvv = self._convert_to_ast(data, size if isinstance(size, int) else None)

        # zero extend if size is greater than len(data_e)
        bit_width = size*self.state.arch.byte_width if isinstance(size, int) else self.state.arch.bits
        if size is not None and self.category == 'reg' and len(data_bvv) < bit_width:
            data_bvv = data_bvv.zero_extend(bit_width - len(data_bvv))

        if type(size) is int:
            size_bvv = self.state.solver.BVV(size, self.state.arch.bits)
        elif size is None:
            size_bvv = self.state.solver.BVV(data_bvv.size() // self.state.arch.byte_width, self.state.arch.bits)
        else:
            size_bvv = size

        if len(data_bvv) % self.state.arch.byte_width != 0:
            raise SimMemoryError("Attempting to store non-byte data to memory")
        if not size_bvv.symbolic and (len(data_bvv) < size_bvv*self.state.arch.byte_width).is_true():
            raise SimMemoryError("Provided data is too short for this memory store")

        return self.store(addr, data_bvv, size=size_bvv, **kwargs)

    def load(self, addr, size=None, **kwargs):
        if size is None:
            size = self.state.arch.bits // self.state.arch.byte_width
        super().load(addr, size=size, **kwargs)

    def _convert_to_ast(self, thing, size=None):
        """
        Make an AST out of concrete @data_e
        """
        if type(thing) is bytes:
            # Convert the string into a BVV, *regardless of endness*
            bits = len(thing) * self.state.arch.byte_width
            return self.state.solver.BVV(thing, bits)
        elif type(thing) is int:
            return self.state.solver.BVV(thing, size*self.state.arch.byte_width if size is not None else self.state.arch.bits)
        else:
            return thing.raw_to_bv()

from ...errors import SimMemoryError
