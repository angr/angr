import simuvex

######################################
# stub, for unsupported syscalls
######################################

#pylint:disable=redefined-builtin,arguments-differ
class stub(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self):
        return self.state.se.Unconstrained("syscall_stub", self.state.arch.bits)
