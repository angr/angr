import angr

class GetProcessHeap(angr.SimProcedure):
    def run(self):
        return 1 # fake heap handle

class HeapCreate(angr.SimProcedure):
    def run(self, flOptions, dwInitialSize, dwMaximumSize):
        return 1 # still a fake heap handle

class HeapAlloc(angr.SimProcedure):
    def run(self, HeapHandle, Flags, Size):
        if self.state.solver.symbolic(Size):
            size = self.state.solver.max_int(Size)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.solver.eval(Size)

        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size
        return addr

class GlobalAlloc(HeapAlloc):
    def run(self, Flags, Size):
        return super(GlobalAlloc, self).run(1, Flags, Size)
