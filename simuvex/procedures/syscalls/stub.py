import simuvex

######################################
# stub, for unsupported syscalls
######################################

#pylint:disable=redefined-builtin,arguments-differ
class stub(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, resolves=None):

        self.resolves = resolves  # pylint:disable=attribute-defined-outside-init

        return self.state.se.Unconstrained("syscall_stub", self.state.arch.bits)

    def __repr__(self):
        if self.resolves:
            return '<Syscall stub (%s)>' % self.resolves
        else:
            return '<Syscall stub>'
