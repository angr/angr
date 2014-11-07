import simuvex

######################################
# recvfrom
######################################

class recvfrom(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231
        # TODO: Symbolic fd
        fd = self.arg(0)
        dst = self.arg(1)
        plugin = self.state['posix']

        # TODO: Now it's limiting UDP package to 25 bytes
        # We need to better handling for this
        length = self.state.BVV(40, self.state.arch.bits)

        old_pos = plugin.pos(fd)
        data = plugin.read(fd, length)
        self.state.store_mem(dst, data)
        self.ret(length)
