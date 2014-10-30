import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# fgets
######################################

class fgets(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231
        # TODO: Symbolic fd
        dst = self.arg(0)
        size = self.arg(1)
        fd = self.arg(2)

        self.argument_types = {2: SimTypeFd(),
                               0: self.ty_ptr(SimTypeArray(SimTypeChar(), size)),
                               1: SimTypeLength(self.state.arch)}
        self.return_type = self.argument_types[0]
        plugin = self.state['posix']

        f = plugin.get_file(fd)
        old_pos = plugin.pos(fd)

        data,constraints = self.state.memory.copy_contents(dst, old_pos, size, src_memory=f.content)
        self.state.add_constraints(*constraints)

        if data is not None:
            self.add_refs(simuvex.SimFileRead(self.addr, self.stmt_from, fd, old_pos, data, size))
            self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dst, data, size))
        self.ret(dst)
