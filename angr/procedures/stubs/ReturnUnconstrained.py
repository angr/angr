import angr

######################################
# Returns an unconstrained byte
######################################

class ReturnUnconstrained(angr.SimProcedure):
    def run(self, resolves=None): #pylint:disable=arguments-differ
        #pylint:disable=attribute-defined-outside-init
        self.resolves = resolves

        if self.successors is not None:
            self.successors.artifacts['resolves'] = resolves

        o = self.state.se.Unconstrained("unconstrained_ret_%s" % self.resolves, self.state.arch.bits)
        #if 'unconstrained_ret_9_64' in o.variables:
        #   __import__('ipdb').set_trace()
        return o

    def __repr__(self):
        if 'resolves' in self.kwargs:
            return '<ReturnUnconstrained %s>' % self.kwargs['resolves']
        else:
            return '<ReturnUnconstrained>'
