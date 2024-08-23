from __future__ import annotations
import angr


class Caller(angr.SimProcedure):
    """
    Caller stub. Creates a Ijk_Call exit to the specified function
    """

    def run(self, target_addr=None, target_cc=None):
        self.call(target_addr, [], "after_call", cc=target_cc, prototype="void x()")

    def after_call(self, target_addr=None, target_cc=None):
        pass
