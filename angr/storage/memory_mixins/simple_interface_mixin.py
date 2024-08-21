import claripy

from . import MemoryMixin
from ...errors import SimMemoryError


class SimpleInterfaceMixin(MemoryMixin):
    def load(self, addr, size=None, endness=None, condition=None, fallback=None, **kwargs):
        tsize = self._translate_size(size, None)
        return super().load(
            self._translate_addr(addr),
            size=tsize,
            endness=self._translate_endness(endness),
            condition=self._translate_cond(condition),
            fallback=self._translate_data(fallback, tsize) if fallback is not None else None,
            **kwargs,
        )

    def store(self, addr, data, size=None, endness=None, condition=None, **kwargs):
        tsize = self._translate_size(size, data)
        super().store(
            self._translate_addr(addr),
            self._translate_data(data, tsize),
            size=tsize,
            endness=self._translate_endness(endness),
            condition=self._translate_cond(condition),
            **kwargs,
        )

    def _translate_addr(self, a):
        if isinstance(a, int):
            return a
        if isinstance(a, claripy.ast.Base) and not a.singlevalued:
            raise SimMemoryError("address not supported")
        return self.state.solver.eval(a)

    def _translate_data(self, d, size):
        if type(d) in (bytes, bytearray):
            return self.state.solver.BVV(d)
        elif type(d) is int:
            return self.state.solver.BVV(d, size * self.state.arch.byte_width)
        elif isinstance(d, claripy.ast.Base):
            return d
        else:
            raise SimMemoryError("data not supported")

    def _translate_size(self, s, data):
        if isinstance(s, int):
            return s
        if isinstance(s, claripy.ast.Base) and not s.singlevalued:
            raise SimMemoryError("size not supported")
        if s is None:
            if isinstance(data, claripy.ast.BV):
                return len(data) // self.state.arch.byte_width
            elif isinstance(data, (bytes, bytearray)):
                return len(data)
            else:
                raise SimMemoryError("unknown size")
        return self.state.solver.eval(s)

    def _translate_cond(self, c):
        if isinstance(c, claripy.ast.Base) and not c.singlevalued:
            raise SimMemoryError("condition not supported")
        if c is None:
            return True
        else:
            return self.state.solver.eval_upto(c, 1)[0]

    def _translate_endness(self, endness):
        if endness is None:
            return self.endness
        else:
            return endness
