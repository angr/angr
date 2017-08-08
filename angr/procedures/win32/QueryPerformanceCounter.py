import angr

class QueryPerformanceCounter(angr.SimProcedure):
    def run(self, ptr):
        self.state.mem[ptr].qword = 0x0000005555555555
        return 1
