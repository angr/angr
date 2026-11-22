from __future__ import annotations

import angr


class ntohl(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, to_convert):
        if self.state.arch.memory_endness == "Iend_LE":
            return to_convert[31:0].reversed.zero_extend(len(to_convert) - 32)
        return to_convert
