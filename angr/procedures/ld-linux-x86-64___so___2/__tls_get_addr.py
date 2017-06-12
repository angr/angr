import simuvex

class __tls_get_addr(simuvex.SimProcedure):
    def run(self, index):
        mod_id = self.state.memory.load(index, self.state.arch.bits / 8, endness=self.state.arch.memory_endness)

        if self.state.se.symbolic(mod_id):
            raise Exception("symbolic TLS module ID -- this shouldn't happen")
        else:
            mod_id = self.state.se.any_int(mod_id)

        offset = self.state.memory.load(index + 4, self.state.arch.bits / 8, endness=self.state.arch.memory_endness)
        return self.state.posix.tls_modules[mod_id] + offset
