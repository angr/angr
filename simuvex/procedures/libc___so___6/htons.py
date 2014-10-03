import simuvex
######################################
# htons (yes, really)
######################################

class htons(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231
        to_convert = self.arg(0)
        if self.state.arch.memory_endness == "Iend_LE":
            self.ret(to_convert.reversed())
        else:
            self.ret(to_convert)
