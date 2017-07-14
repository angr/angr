import angr

class GetSystemTimeAsFileTime(angr.SimProcedure):
    def run(self, outptr):
        # claim that 400 years have elapsed since Jan 1, 1601
        self.state.mem[outptr].qword = 1000 / 100 * 1000 * 1000 * 60 * 60 * 24 * 365 * 400
