import angr


class EncodePointer(angr.SimProcedure):
    def run(self, ptr):
        return ptr
