import angr
import logging

l = logging.getLogger(name=__name__)


class getcwd(angr.SimProcedure):
    def run(self, buf, size):
        if self.state.solver.unique(size):
            size = self.state.solver.eval_one(size)

        cwd = self.state.fs.cwd + b"\0"
        if len(cwd) > size:
            return -self.state.posix.ERANGE
        try:
            self.state.memory.store(buf, cwd, size=len(cwd))
        except angr.errors.SimSegfaultException:
            return -self.state.posix.EFAULT
        return len(cwd)


class chdir(angr.SimProcedure):
    def run(self, buf):
        cwd = self.state.mem[buf].string.concrete
        l.info("chdir(%r)", cwd)
        self.state.fs.cwd = cwd
        return 0
