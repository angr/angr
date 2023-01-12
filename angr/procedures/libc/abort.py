import angr

######################################
# abort
######################################


class abort(angr.SimProcedure):
    NO_RET = True

    def run(self):
        self.exit(1)
