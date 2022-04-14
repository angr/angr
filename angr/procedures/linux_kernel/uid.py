import angr

class getuid(angr.SimProcedure):
    def run(self):
        return self.state.posix.uid

class getgid(angr.SimProcedure):
    def run(self):
        return self.state.posix.gid

class getresgid(angr.SimProcedure):
    def run(self, rgid_addr, egid_addr, sgid_addr):
        gid = self.state.posix.gid
        self.state.memory.store(rgid_addr, gid)
        self.state.memory.store(egid_addr, gid)
        self.state.memory.store(sgid_addr, gid)
        return 0

class getresuid(angr.SimProcedure):
    def run(self, ruid_addr, euid_addr, suid_addr):
        uid = self.state.posix.uid
        self.state.memory.store(ruid_addr, uid)
        self.state.memory.store(euid_addr, uid)
        self.state.memory.store(suid_addr, uid)
        return 0
