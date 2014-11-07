import simuvex

######################################
# send
######################################

class send(simuvex.SimProcedure):
    def __init__(self): #pylint:disable=W0231
        fd = self.arg(0)
        src = self.arg(1)
        length = self.arg(2)

        data = self.state.mem_expr(src, length)
        plugin = self.state['posix']
        length = plugin.write(fd, data, length)

        self.ret(length)
