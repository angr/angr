import angr
from angr.sim_type import SimTypeString

######################################
# gets
######################################

class gets(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):
        DELIMITERS = ["\x00", "\x09", "\x0a", "\x0b", "\x0d", "\x20"]
        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = self.argument_types[0]

        f = self.state.posix.get_file(0)
        region = f.content
        position = f.pos

        max_str_len = self.state.libc.max_str_len
        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        limit = max_str_len

        ohr, ohc, ohi = region.find(position, self.state.se.BVV('\n'), limit, max_symbolic_bytes=max_symbolic_bytes)
                    
        mm = self.state.se.If(ohr == 0, position + max_str_len, ohr)
        length = self.state.se.max_int(mm - position)
        src_str = region.load(position, length)

        for delimiter in set(DELIMITERS) - {'\x00'}:
            delim_bvv = self.state.se.BVV(delimiter)
            for i in range(length):
                self.state.add_constraints(region.load(position + i, 1) != delim_bvv)

        self.state.memory.store(string, src_str)
        self.state.memory.store(string + length, self.state.se.BVV(0, 8))

        return string


        
