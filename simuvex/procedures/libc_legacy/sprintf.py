import simuvex

######################################
# sprintf
######################################

class sprintf(simuvex.SimProcedure):
    def __init__(self):
        # TODO: Better support
        str_ptr = self.get_arg_value(0)
        fmt_string = self.get_arg_value(1)
        data = self.get_arg_value(2)
        self.exit_return(3)
