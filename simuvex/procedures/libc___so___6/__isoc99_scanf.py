import simuvex

######################################
# __isoc99_scanf
######################################

class __isoc99_scanf(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fmt_str): #pylint:disable=unused-argument
        # TODO: Access different registers on different archs
        # TODO: handle symbolic and static modes
        fd = 0 # always stdin

        # TODO: Now we assume it's always '%s'
        dst = self.arg(1)
        length = 4 # TODO: Symbolic length

        data = self.state.posix.read_from(fd, length)
        self.state.memory.store(dst, data)
        return dst
