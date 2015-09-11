import simuvex
from simuvex.s_type import SimTypeInt

######################################
# getchar
######################################

class getchar(simuvex.SimProcedure):
    def run(self):
        self.return_type = SimTypeInt(32, True)
        data = self.state.posix.read_from(0,1)
        data = data.zero_extend(self.state.arch.bits-data.size())
        return data
