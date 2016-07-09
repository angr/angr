#!/usr/bin/env python

from .plugin import SimStatePlugin
class SimProcedureData(SimStatePlugin):
    def __init__(self):
        SimStatePlugin.__init__(self)

        self.hook_addr = 0
        self.callstack = []

    def copy(self):
        out = SimProcedureData()
        out.hook_addr = self.hook_addr
        out.callstack = list(self.callstack)
        return out

    def merge(self, others, merge_conditions):
        return False

    def widen(self, others):
        return False

    def clear(self):
        s = self.state
        self.__init__()
        self.state = s

SimProcedureData.register_default('procedure_data', SimProcedureData)
