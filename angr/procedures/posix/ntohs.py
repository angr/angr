from __future__ import annotations

import angr


class ntohs(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, to_convert):
        if self.state.arch.memory_endness == "Iend_LE":
            return to_convert[15:0].reversed.zero_extend(len(to_convert) - 16)
        return to_convert
