from __future__ import annotations

import logging

import angr
from angr import claripy
from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)


class asprintf(FormatParser):
    # int asprintf(char **strp, const char *fmt, ...);
    #
    # Like sprintf, but allocates the destination buffer (output length + 1 for
    # the NUL), writes the buffer pointer to *strp, and returns the number of
    # bytes written (excluding the NUL). pylint: disable=arguments-differ
    def run(self, str_ptrptr, fmt):  # pylint:disable=unused-argument
        # The format str is at index 1
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)
        length = out_str.size() // self.arch.byte_width

        # Allocate length + 1 bytes for the formatted string and its terminator.
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        dst = self.inline_call(malloc, length + 1).ret_expr

        self.state.memory.store(dst, out_str)
        # Terminating NUL byte
        self.state.memory.store(dst + length, claripy.BVV(0, self.arch.byte_width))

        # Write the allocated buffer pointer back to *strp.
        self.state.memory.store(str_ptrptr, dst, endness=self.arch.memory_endness)

        return length
