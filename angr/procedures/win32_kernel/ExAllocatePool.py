# pylint: disable=missing-class-docstring
import claripy

import angr


class ExAllocatePool(angr.SimProcedure):
    def run(self, PoolType, NumberOfBytes):  # pylint:disable=arguments-differ, unused-argument
        addr = self.state.heap._malloc(NumberOfBytes)
        memset = angr.SIM_PROCEDURES["libc"]["memset"]
        self.inline_call(memset, addr, claripy.BVV(0, 8), NumberOfBytes)  # zerofill
        return addr
