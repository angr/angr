import simuvex

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        ret = self.state.posix.read(file_ptr, dst, size * nm)
        return self.state.se.If(self.state.se.Or(size == 0, nm == 0), 0, ret / size)
