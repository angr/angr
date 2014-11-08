import simuvex

######################################
# read
######################################

class read(simuvex.SimProcedure):
    def analyze(self):
        # TODO: Symbolic fd
        fd = self.arg(0)
        dst = self.arg(1)
        length = self.arg(2)
        plugin = self.state['posix']

        # TODO handle errors
        data = plugin.read(fd, length)
        self.state.store_mem(dst, data)

        return length
