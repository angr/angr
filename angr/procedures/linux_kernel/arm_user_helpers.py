import angr

class _kernel_user_helper_get_tls(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        self.state.regs.r0 = self.project.loader.tls_object.user_thread_pointer
        return
