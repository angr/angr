from __future__ import annotations
import angr


class stpcpy(angr.SimProcedure):
    """stpcpy"""

    # pylint:disable=arguments-differ

    def run(self, dst, src):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]
        src_len = self.inline_call(strlen, src)

        return (
            self.inline_call(strncpy, dst, src, src_len.ret_expr + 1, src_len=src_len.ret_expr).ret_expr
            + src_len.ret_expr
        )
