import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# fgets
######################################

class fgets(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, fd):
        self.argument_types = {2: SimTypeFd(),
                               0: self.ty_ptr(SimTypeArray(SimTypeChar(), size)),
                               1: SimTypeLength(self.state.arch)}
        self.return_type = self.argument_types[0]

        f = self.state.posix.get_file(fd)
        old_pos = self.state.posix.pos(fd)

        self.state.memory.copy_contents(dst, old_pos, size, src_memory=f.content)
        f.seek(old_pos + size)

        return dst
