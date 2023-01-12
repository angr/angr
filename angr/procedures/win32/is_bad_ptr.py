import angr


class IsBadReadPtr(angr.SimProcedure):
    def run(self, ptr, length):
        try:
            return (~self.state.memory.permissions(ptr)[0]).zero_extend(self.state.arch.bits - 1)
        except angr.errors.SimMemoryError:
            return 1


class IsBadWritePtr(angr.SimProcedure):
    def run(self, ptr, length):
        try:
            return (~self.state.memory.permissions(ptr)[1]).zero_extend(self.state.arch.bits - 1)
        except angr.errors.SimMemoryError:
            return 1


class IsBadCodePtr(angr.SimProcedure):
    def run(self, ptr, length):
        try:
            return (~self.state.memory.permissions(ptr)[2]).zero_extend(self.state.arch.bits - 1)
        except angr.errors.SimMemoryError:
            return 1
