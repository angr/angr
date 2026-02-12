from __future__ import annotations

import angr


class strncasecmp(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, a_addr, b_addr, n):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]

        a_strlen = self.inline_call(strlen, a_addr)
        b_strlen = self.inline_call(strlen, b_addr)

        strncmp = self.inline_call(
            angr.SIM_PROCEDURES["libc"]["strncmp"],
            a_addr,
            b_addr,
            n,
            a_len=a_strlen,
            b_len=b_strlen,
            ignore_case=True,
        )
        return strncmp.ret_expr
