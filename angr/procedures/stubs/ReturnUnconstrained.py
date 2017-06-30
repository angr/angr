import angr

######################################
# Returns an unconstrained byte
######################################

class ReturnUnconstrained(angr.SimProcedure):
    def run(self, resolves=None, return_val=None): #pylint:disable=arguments-differ
        #pylint:disable=attribute-defined-outside-init
        self.resolves = resolves
        if resolves is not None:
            self.display_name = '%s (stub)' % resolves

        if self.successors is not None:
            self.successors.artifacts['resolves'] = resolves

        if return_val is None:
            o = self.state.se.Unconstrained("unconstrained_ret_%s" % self.resolves, self.state.arch.bits)
        else:
            o = return_val

        return o

    def __repr__(self):
        if 'resolves' in self.kwargs:
            return '<ReturnUnconstrained %s>' % self.kwargs['resolves']
        else:
            return '<ReturnUnconstrained>'
