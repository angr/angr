import angr
import claripy

class GetTempPathA(angr.SimProcedure):
    RESULT = claripy.BVV(b"C:\\Temp\\")

    def run(self, nBufferLength, lpBuffer):
        try:
            length = self.state.solver.eval_one(nBufferLength)
        except angr.errors.SimValueError:
            raise angr.errors.SimProcedureError("Can't handle symbolic nBufferLength in GetTempPath")

        copy_len = min(self.RESULT.length//8, length - 1)
        self.state.memory.store(lpBuffer, self.RESULT[self.RESULT.length - 1 : self.RESULT.length - copy_len*8].concat(claripy.BVV(0, 8)))
        return self.RESULT.length // 8

class GetWindowsDirectoryA(angr.SimProcedure):
    RESULT = claripy.BVV(b"C:\\Windows")

    def run(self, lpBuffer, uSize):
        try:
            length = self.state.solver.eval_one(uSize)
        except angr.errors.SimValueError:
            raise angr.errors.SimProcedureError("Can't handle symbolic uSize in GetWindowsDirectory")

        copy_len = min(self.RESULT.length//8, length - 1)
        self.state.memory.store(lpBuffer, self.RESULT[self.RESULT.length - 1 : self.RESULT.length - copy_len*8].concat(claripy.BVV(0, 8)))
        return self.RESULT.length // 8
