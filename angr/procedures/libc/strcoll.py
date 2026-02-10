from __future__ import annotations

import angr


class strcoll(angr.SimProcedure):
    """Locale-aware string comparison."""

    # pylint:disable=arguments-differ

    def run(self, s1, s2):
        strcmp = angr.SIM_PROCEDURES["libc"]["strcmp"]

        # Defaults to strcmp, if the current locale is "C" or "POSIX".
        return self.inline_call(strcmp, s1, s2).ret_expr
