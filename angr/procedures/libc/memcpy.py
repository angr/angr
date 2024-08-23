from __future__ import annotations
import angr
import logging

l = logging.getLogger(name=__name__)


class memcpy(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):
        if not self.state.solver.symbolic(limit):
            # not symbolic so we just take the value
            conditional_size = self.state.solver.eval(limit)
        else:
            # constraints on the limit are added during the store
            max_memcpy_size = self.state.libc.max_memcpy_size
            max_limit = self.state.solver.max_int(limit)
            min_limit = self.state.solver.min_int(limit)
            conditional_size = min(max_memcpy_size, max(min_limit, max_limit))
            if max_limit > max_memcpy_size and conditional_size < max_limit:
                l.warning(
                    "memcpy upper bound of %#x outside limit, limiting to %#x instead", max_limit, conditional_size
                )

        l.debug("Memcpy running with conditional_size %#x", conditional_size)

        if conditional_size > 0:
            src_mem = self.state.memory.load(src_addr, conditional_size, endness="Iend_BE")
            if ABSTRACT_MEMORY in self.state.options:
                self.state.memory.store(dst_addr, src_mem, size=conditional_size, endness="Iend_BE")
            else:
                self.state.memory.store(dst_addr, src_mem, size=limit, endness="Iend_BE")

        return dst_addr


from ...sim_options import ABSTRACT_MEMORY
