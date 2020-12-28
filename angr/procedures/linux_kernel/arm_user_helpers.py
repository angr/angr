import angr

"""
references:
https://elixir.bootlin.com/linux/latest/source/arch/arm/kernel/entry-armv.S
https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt
"""

class _kuser_helper_version(angr.SimProcedure):
    # pylint: disable=arguments-differ
    kuser_addr = 0xffff0ffc
    def run(self):
        # hardcoded version number extracted from QEMU
        self.state.regs.r0 = 0x884c0
        return

class _kuser_helper_get_tls(angr.SimProcedure):
    # pylint: disable=arguments-differ
    kuser_addr = 0xffff0fe0
    def run(self):
        self.state.regs.r0 = self.project.loader.tls.threads[0].user_thread_pointer
        return

class _kuser_cmpxchg(angr.SimProcedure):
    # pylint: disable=arguments-differ
    kuser_addr = 0xffff0fc0
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

class _kuser_memory_barrier(angr.SimProcedure):
    # pylint: disable=arguments-differ
    kuser_addr = 0xffff0fa0
    def run(self):
        pass

class _kuser_cmpxchg64(angr.SimProcedure):
    # pylint: disable=arguments-differ
    kuser_addr = 0xffff0f60
    def run(self):
        raise NotImplementedError(f"{self.__class__.__name__} is not implemented")
