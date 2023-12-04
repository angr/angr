# pylint: disable=missing-class-docstring
from angr import SimProcedure


class ExFreePoolWithTag(SimProcedure):
    def run(self, P, Tag):  # pylint:disable=arguments-differ, unused-argument
        self.state.heap._free(P)
