from __future__ import annotations

import angr

from .vprintf import as_return, unmodeled_format_length


class vsprintf(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, dst_ptr, fmt, ap):
        length = unmodeled_format_length(self, fmt)
        memcpy = angr.SIM_PROCEDURES["libc"]["memcpy"]
        self.inline_call(memcpy, dst_ptr, fmt, length + 1)
        return as_return(self, length)


class __vsprintf_chk(vsprintf):
    def run(self, dst_ptr, flag, slen, fmt, ap):  # type:ignore[reportIncompatibleMethodOverride] # pylint:disable=arguments-differ,unused-argument
        return super().run(dst_ptr, fmt, ap)
