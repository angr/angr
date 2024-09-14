from __future__ import annotations
import claripy

import angr


class crazy_scanf(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, src, fmt, one, two, three):  # pylint:disable=unused-argument
        memcpy = angr.SIM_PROCEDURES["libc"]["memcpy"]

        self.inline_call(memcpy, one, src, 5)
        self.state.memory.store(one + 4, claripy.BVV(0, 8))
        self.inline_call(memcpy, two, src + 6, 8192)
        self.state.memory.store(two + 8191, claripy.BVV(0, 8))
        self.inline_call(memcpy, three, src + 6 + 8193, 12)
        self.state.memory.store(three + 11, claripy.BVV(0, 8))

        return claripy.BVV(3)
