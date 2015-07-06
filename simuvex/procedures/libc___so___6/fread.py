import simuvex

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        _ = self.state.posix.pos(file_ptr)
        data = self.state.posix.read(file_ptr, size * nm)
        self.state.memory.store(dst, data)
        return size #TODO: handle reading less than nm items somewhere
