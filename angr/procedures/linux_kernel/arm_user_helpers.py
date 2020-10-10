import angr

# pylint: disable=arguments-differ
class _kernel_user_helper_get_tls(angr.SimProcedure):
    def run(self):
        self.state.regs.r0 = self.project.loader.tls.threads[0].user_thread_pointer
        return

class _kernel_cmpxchg(angr.SimProcedure):
    def run(self, oldval, newval, ptr):
        currentval = self.state.mem[ptr].dword.resolved
        success = currentval == oldval
        self.state.memory.store(ptr, newval, condition=success)

        # set flags
        retval = currentval - oldval
        self.state.regs.cc_op = 2
        self.state.regs.cc_dep1 = 0
        self.state.regs.cc_dep2 = retval
        self.state.regs.cc_ndep = 0
        return retval
