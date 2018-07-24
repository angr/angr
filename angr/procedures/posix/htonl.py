import angr
######################################
# htonl
######################################

class htonl(angr.SimProcedure):

    def run(self, to_convert):
        if self.state.arch.memory_endness == "Iend_LE":
            return to_convert.reversed
        else:
            return to_convert
