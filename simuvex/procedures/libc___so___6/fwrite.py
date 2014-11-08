import simuvex

######################################
# write
######################################

class fwrite(simuvex.SimProcedure):
    def analyze(self):
        # TODO: Symbolic fd
        plugin = self.state.get_plugin('posix')
        src = self.arg(0)
        size = self.arg(1)
        nmemb = self.arg(2)
        file_ptr = self.arg(3)

        # TODO handle errors
        data = self.state.mem_expr(src, size, "Iend_BE")
        written = plugin.write(file_ptr, data, size*nmemb)

        return written
