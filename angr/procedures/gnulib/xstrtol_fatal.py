import angr

######################################
# xstrtol_fatal
######################################


class xstrtol_fatal(angr.SimProcedure):
    NO_RET = True

    def run(self, err, opt_idx, c, long_options, arg):
        self.exit(1)
