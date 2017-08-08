import angr

class GetModuleHandleA(angr.SimProcedure):
    def run(self, pointer):
        if self.state.se.is_true(pointer == 0):
            return self.handle(None)
        else:
            return self.handle(self.state.mem[pointer].string.concrete)

    def handle(self, module_name):
        if module_name is None:
            obj = self.project.loader.main_object
        else:
            for name in self.project.loader.shared_objects:
                if name.lower() == module_name.lower():
                    obj = self.project.loader.shared_objects[name]
                    break
                else:
                    return 0
        return obj.mapped_base

class GetModuleHandleW(GetModuleHandleA):
    def run(self, pointer):
        if self.state.se.is_true(pointer == 0):
            return self.handle(None)
        else:
            return self.handle(self.state.mem[pointer].wstring.concrete)
