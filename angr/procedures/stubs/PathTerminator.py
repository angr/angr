import angr

######################################
# Path terminator
######################################


class PathTerminator(angr.SimProcedure):
    NO_RET = True

    def run(self):
        return
