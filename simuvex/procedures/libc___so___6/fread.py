import simuvex

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        ret = self.state.posix.read(file_ptr, dst, size * nm)
        return ret #TODO: handle reading less than nm items somewhere
