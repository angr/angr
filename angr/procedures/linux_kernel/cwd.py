import angr
import logging

l = logging.getLogger(name=__name__)

class getcwd(angr.SimProcedure):
    def run(self, buf, size):
        cwd = self.state.fs.cwd
        size = self.state.solver.If(size-1 > len(cwd), len(cwd), size-1)
        try:
            self.state.memory.store(buf, cwd, size=size)
            self.state.memory.store(buf + size, b'\0')
        except angr.errors.SimSegfaultException:
            return 0
        else:
            return buf

class chdir(angr.SimProcedure):
    def run(self, buf):
        cwd = self.state.mem[buf].string
        l.info('chdir(%r)', cwd)
        self.state.fs.cwd = cwd
        return 0
