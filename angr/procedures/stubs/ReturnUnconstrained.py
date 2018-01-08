import angr

######################################
# Returns an unconstrained byte
######################################

class ReturnUnconstrained(angr.SimProcedure):
    def run(self, return_val=None): #pylint:disable=arguments-differ
        #pylint:disable=attribute-defined-outside-init

        if return_val is None:
            o = self.state.se.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name))
        else:
            o = return_val

        return o
