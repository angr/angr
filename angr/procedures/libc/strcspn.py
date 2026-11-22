from __future__ import annotations

import angr
from angr.procedures.libc.strspn import scan_span


class strcspn(angr.SimProcedure):
    """``strcspn(s, reject)``: length of the initial segment of ``s`` consisting of bytes **not** in ``reject``.

    The ``reject`` set must be a concrete NUL-terminated string; for a symbolic ``reject``
    an unconstrained result is returned (the same over-approximation the rest of angr falls
    back to when a value cannot be modelled). For symbolic ``s``, the scan is bounded by
    ``state.libc.max_str_len`` bytes.
    """

    # pylint:disable=arguments-differ

    def run(self, s_addr, reject_addr):
        return scan_span(self, s_addr, reject_addr, complement=True, name="strcspn")
