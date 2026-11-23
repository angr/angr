from __future__ import annotations

import logging

import angr
from angr import claripy

l = logging.getLogger(name=__name__)


def concrete_cstring(state, addr) -> bytes | None:
    """Read a concrete NUL-terminated string up to ``state.libc.max_str_len`` bytes, or return ``None``."""
    if state.solver.symbolic(addr):
        return None
    out = bytearray()
    for i in range(state.libc.max_str_len):
        try:
            byte = state.memory.load(addr + i, 1, endness=state.arch.memory_endness)
        except angr.errors.SimMemoryError:
            return None
        if state.solver.symbolic(byte):
            return None
        value = state.solver.eval(byte)
        if value == 0:
            return bytes(out)
        out.append(value)
    return None


def concrete_bytes(state, addr, length: int) -> bytes | None:
    """Read ``length`` concrete bytes starting at ``addr``, or return ``None`` if symbolic or unmapped."""
    if state.solver.symbolic(addr):
        return None
    out = bytearray()
    for i in range(length):
        try:
            byte = state.memory.load(addr + i, 1, endness=state.arch.memory_endness)
        except angr.errors.SimMemoryError:
            return None
        if state.solver.symbolic(byte):
            return None
        out.append(state.solver.eval(byte))
    return bytes(out)


def scan_concrete_or_limit(proc: angr.SimProcedure, s_addr) -> tuple[bytes | None, int]:
    """Return ``(concrete_bytes, scan_limit)`` for ``s_addr`` without truncating concrete strings."""
    state = proc.state
    max_str_len = state.libc.max_str_len
    str_len = proc.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_addr)
    if state.solver.symbolic(str_len.ret_expr):
        return None, min(state.solver.max_int(str_len.ret_expr) + 1, max_str_len)
    exact_len = state.solver.eval(str_len.ret_expr) + 1
    data = concrete_bytes(state, s_addr, exact_len)
    if data is not None:
        return data, exact_len
    return None, min(exact_len, max_str_len)


def scan_span(proc: angr.SimProcedure, s_addr, set_addr, *, complement: bool, name: str):
    """Shared implementation for ``strspn`` (``complement=False``) and ``strcspn`` (``complement=True``)."""
    state = proc.state
    bits = state.arch.bits
    endness = state.arch.memory_endness
    set_kind = "reject" if complement else "accept"

    chars = concrete_cstring(state, set_addr)
    if chars is None:
        l.warning("%s: symbolic %s set, returning an unconstrained length", name, set_kind)
        return state.solver.BVS(name, bits, key=("api", name))
    if not chars:
        if complement:
            # nothing is rejected, so the span covers the whole string:
            # strcspn(s, "") == strlen(s)  (note: strspn(s, "") == 0 instead)
            return proc.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_addr).ret_expr
        return claripy.BVV(0, bits)

    char_set = set(chars)
    data, limit = scan_concrete_or_limit(proc, s_addr)
    if data is not None:
        count = 0
        for byte in data:
            if byte == 0 or (byte in char_set) == complement:
                break
            count += 1
        return claripy.BVV(count, bits)

    char_sorted = sorted(char_set)
    l.debug("%s: symbolic string, scanning up to %d bytes", name, limit)
    still = claripy.BoolV(True)
    count = claripy.BVV(0, bits)
    for i in range(limit):
        byte = state.memory.load(s_addr + i, 1, endness=endness)
        in_set = claripy.Or(*[byte == b for b in char_sorted])
        matches = claripy.Not(in_set) if complement else in_set
        step = claripy.And(still, byte != 0, matches)
        step_bv = claripy.If(step, claripy.BVV(1, 1), claripy.BVV(0, 1))
        count = count + claripy.ZeroExt(bits - 1, step_bv)
        still = step
    return count


class strspn(angr.SimProcedure):
    """``strspn(s, accept)``: length of the initial segment of ``s`` consisting only of bytes from ``accept``.

    The ``accept`` set must be a concrete NUL-terminated string; for a symbolic ``accept``
    an unconstrained result is returned (the same over-approximation the rest of angr falls
    back to when a value cannot be modelled). For symbolic ``s``, the scan is bounded by
    ``state.libc.max_str_len`` bytes.
    """

    # pylint:disable=arguments-differ

    def run(self, s_addr, accept_addr):
        return scan_span(self, s_addr, accept_addr, complement=False, name="strspn")
