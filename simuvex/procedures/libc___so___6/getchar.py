import simuvex
from simuvex.s_type import SimTypeInt

######################################
# getchar
######################################

class getchar(simuvex.SimProcedure):
    def __init__(self): #pylint:disable=W0231
        self.return_type = SimTypeInt(32, True)
        plugin = self.state['posix']

        old_pos = plugin.pos(0)
        data = plugin.read(0,1)
        self.add_refs(simuvex.SimFileRead(self.addr, self.stmt_from, 0, old_pos, data, 1))
        data = data.zero_extend(self.state.arch.bits-data.size())
        self.ret(data)
