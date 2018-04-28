import angr

class getuid(angr.SimProcedure):
    def run(self):
        return self.state.posix.uid

class getgid(angr.SimProcedure):
    def run(self):
        return self.state.posix.gid
