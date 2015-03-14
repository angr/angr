import simuvex

######################################
# __vsnprintf
######################################

class vsnprintf(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, str_ptr, size, fmt, ap): #pylint:disable=unused-argument
        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now
        return size - 1
