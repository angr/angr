from __future__ import annotations

import logging

from angr import claripy
from angr.procedures.libc.getdelim import getdelim

l = logging.getLogger(name=__name__)


class getline(getdelim):
    # getline(lineptr, n, stream) == getdelim(lineptr, n, '\n', stream).
    # Reuse the getdelim read/realloc logic with a fixed newline delimiter.
    # pylint: disable=arguments-differ
    def run(self, line_ptrptr, len_ptr, file_ptr):
        delim = claripy.BVV(ord("\n"), self.arch.byte_width)
        return super().run(line_ptrptr, len_ptr, delim, file_ptr)
