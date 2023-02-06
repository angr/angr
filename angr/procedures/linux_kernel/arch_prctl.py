import angr


######################################
# arch_prctl
######################################
class arch_prctl(angr.SimProcedure):
    """
    Sets the architecture specific thread state based on the subfunction selected
    using the 'code' parameter. This syscall is only present on x86_64 linux
    """

    def run(self, code, addr):  # pylint: disable=arguments-differ
        if self.state.solver.symbolic(code):
            raise angr.errors.SimValueError("Code value passed to arch_prctl must be concrete.")

        code = self.state.solver.eval(code)

        # ARCH_SET_GS
        if code == 0x1001:
            self.state.regs.gs = addr
        # ARCH_SET_FS
        elif code == 0x1002:
            self.state.regs.fs = addr
        # ARCH_GET_FS
        elif code == 0x1003:
            fs = self.state.regs.fs
            self.state.memory.store(addr, fs)
        # ARCH_GET_GS
        elif code == 0x1004:
            gs = self.state.regs.gs
            self.state.memory.store(addr, gs)
        else:
            # EINVAL is returned if code is not a valid subcommand.
            return 22
        return 0
