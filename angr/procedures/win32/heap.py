import angr


class GetProcessHeap(angr.SimProcedure):
    def run(self):
        return 1  # fake heap handle


class HeapCreate(angr.SimProcedure):
    def run(self, flOptions, dwInitialSize, dwMaximumSize): #pylint:disable=arguments-differ, unused-argument
        return 1  # still a fake heap handle


class HeapAlloc(angr.SimProcedure):
    def run(self, HeapHandle, Flags, Size): #pylint:disable=arguments-differ, unused-argument
        return self.state.heap._malloc(Size)


class GlobalAlloc(HeapAlloc):
    def run(self, Flags, Size):
        return super(GlobalAlloc, self).run(1, Flags, Size)


class HeapFree(angr.SimProcedure):
    def run(self, HeapHandle, Flags, lpMem): #pylint:disable=arguments-differ, unused-argument
        return 1
