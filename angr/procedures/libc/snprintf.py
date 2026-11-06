from __future__ import annotations

import logging

from angr import claripy
from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)


def _store_snprintf_result(proc, dst_ptr, size, out_str):
    out_len = out_str.size() // proc.arch.byte_width

    # snprintf writes at most size - 1 bytes, followed by a NUL when size is
    # non-zero. Keep the existing concretization policy used by vsnprintf so
    # symbolic sizes do not pick an unconstrained write bound.
    concrete_size = proc.state.solver.eval(size)
    proc.state.add_constraints(size == concrete_size)
    if concrete_size == 0:
        return out_len

    write_len = min(out_len, concrete_size - 1)
    if write_len > 0:
        proc.state.memory.store(dst_ptr, out_str.get_bytes(0, write_len))

    proc.state.memory.store(dst_ptr + write_len, claripy.BVV(0, proc.arch.byte_width))
    return out_len


class snprintf(FormatParser):
    def run(self, dst_ptr, size, fmt):  # pylint:disable=arguments-differ,unused-argument
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)
        return _store_snprintf_result(self, dst_ptr, size, out_str)


class __snprintf_chk(FormatParser):
    def run(self, dst_ptr, maxlen, flag, size, fmt):  # pylint:disable=arguments-differ,unused-argument
        # The format str is at index 4
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)
        return _store_snprintf_result(self, dst_ptr, maxlen, out_str)
