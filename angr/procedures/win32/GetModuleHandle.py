from __future__ import annotations
import angr
import logging

l = logging.getLogger(name=__name__)


class GetModuleHandleA(angr.SimProcedure):
    def run(self, pointer):
        if self.state.solver.is_true(pointer == 0):
            return self.handle(None)
        return self.handle(self.state.mem[pointer].string.concrete.decode("utf-8"))

    def handle(self, module_name):
        if module_name is None:
            obj = self.project.loader.main_object
        else:
            obj = self.project.loader.find_object(module_name)
            if obj is None:
                l.info('GetModuleHandle: No loaded object named "%s"', module_name)
                return 0
        return obj.mapped_base


class GetModuleHandleW(GetModuleHandleA):
    def run(self, pointer):
        if self.state.solver.is_true(pointer == 0):
            return self.handle(None)
        return self.handle(self.state.mem[pointer].wstring.concrete)
