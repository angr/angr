import simuvex

######################################
# __isoc99_scanf
######################################

class __isoc99_scanf(simuvex.SimProcedure):
    def __init__(self): #pylint:disable=W0231
        # TODO: Access different registers on different archs
        # TODO: handle symbolic and static modes
        fd = 0 # always stdin
        fmt_str = self.arg(0)
        # TODO: Now we assume it's always '%s'
        dst = self.arg(1)
        length = 17 # TODO: Symbolic length
        plugin = self.state['posix']

        data = plugin.read(fd, length)
        self.state.store_mem(dst, data)
        self.ret(dst)
