from __future__ import annotations

import logging

import angr
from angr import claripy
from angr.procedures.libc.strspn import concrete_cstring, scan_concrete_or_limit

l = logging.getLogger(name=__name__)


class strpbrk(angr.SimProcedure):
    """``strpbrk(s, accept)``: pointer to the **first** byte of ``s`` that also occurs in ``accept``.

    Returns a NULL pointer when no byte of ``s`` occurs in ``accept``.

    The ``accept`` set must be a concrete NUL-terminated string; for a symbolic ``accept``
    a NULL pointer cannot be ruled out, so an unconstrained pointer is returned. For symbolic
    ``s``, the scan is bounded by ``state.libc.max_str_len`` bytes.
    """

    # pylint:disable=arguments-differ

    def run(self, s_addr, accept_addr):
        bits = self.state.arch.bits
        endness = self.state.arch.memory_endness
        null = claripy.BVV(0, bits)

        accept = concrete_cstring(self.state, accept_addr)
        if accept is None:
            l.warning("strpbrk: symbolic accept set, returning an unconstrained pointer")
            return self.state.solver.BVS("strpbrk", bits, key=("api", "strpbrk"))
        if not accept:
            return null

        accept_set = set(accept)
        data, limit = scan_concrete_or_limit(self, s_addr)
        if data is not None:
            for i, byte in enumerate(data):
                if byte == 0:
                    break
                if byte in accept_set:
                    return s_addr + i
            return null

        accept_sorted = sorted(accept_set)
        l.debug("strpbrk: symbolic string, scanning up to %d bytes", limit)
        result = null
        alive = claripy.BoolV(True)
        for i in range(limit):
            byte = self.state.memory.load(s_addr + i, 1, endness=endness)
            in_set = claripy.Or(*[byte == b for b in accept_sorted])
            hit = claripy.And(alive, byte != 0, in_set)
            result = claripy.If(hit, s_addr + i, result)
            alive = claripy.And(alive, byte != 0, claripy.Not(in_set))
        return result
