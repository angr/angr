import angr

# these are NOT suitable for multibyte characters
class CharNextA(angr.SimProcedure):
    def run(self, ptr):
        return self.state.solver.If(self.state.mem[ptr].uint8_t.resolved == 0, ptr, ptr + 1)

class CharPrevA(angr.SimProcedure):
    def run(self, start, ptr):
        return self.state.solver.If(start == ptr, start, ptr - 1)
