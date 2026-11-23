from __future__ import annotations

import angr


class strrchr(angr.SimProcedure):
    """``strrchr(s, c)``: pointer to the **last** occurrence of ``c`` in the NUL-terminated string ``s``.

    Returns a NULL pointer when ``c`` does not occur in ``s`` (and, as specified by C,
    the pointer to the terminating NUL when ``c`` is ``0``).
    """

    # pylint:disable=arguments-differ

    def run(self, s_addr, c_int):
        str_len = self.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_addr)
        return self.inline_call(angr.SIM_PROCEDURES["libc"]["memrchr"], s_addr, c_int, str_len.ret_expr + 1).ret_expr
