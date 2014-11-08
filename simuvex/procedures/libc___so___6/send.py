import simuvex

######################################
# send
######################################

class send(simuvex.SimProcedure):
    def analyze(self):
        fd = self.arg(0)
        src = self.arg(1)
        length = self.arg(2)

        data = self.state.mem_expr(src, length)
        plugin = self.state['posix']
        length = plugin.write(fd, data, length)

        return length
