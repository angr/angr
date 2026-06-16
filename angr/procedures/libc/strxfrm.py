from __future__ import annotations

import angr


class strxfrm(angr.SimProcedure):
    """Transform string for locale-aware comparison."""

    # pylint:disable=arguments-differ

    def run(self, dest, src, n):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]
        src_len = self.inline_call(strlen, src)

        # Defaults to strcpy, if the current locale is "C" or "POSIX".
        self.inline_call(strncpy, dest, src, n, src_len=src_len.ret_expr)

        return src_len.ret_expr
