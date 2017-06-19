import simuvex

######################################
# putchar
######################################

class putchar(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):
        self.state.posix.write(1, string[7:0], 1)
        return string[7:0].zero_extend(self.state.arch.bits - 8)
