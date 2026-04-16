from __future__ import annotations
import angr


class strndup(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, s, n):
        strnlen = angr.SIM_PROCEDURES["libc"]["strnlen"]
        memcpy = angr.SIM_PROCEDURES["libc"]["memcpy"]
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]

        src_len = self.inline_call(strnlen, s, n).ret_expr
        new_s = self.inline_call(malloc, src_len + 1).ret_expr

        self.inline_call(memcpy, new_s, s, src_len)

        return new_s
