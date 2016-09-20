import simuvex

######################################
# arch_prctl
######################################
"""
Represents the arch_prctl system call present on x86-64 Linux.
"""
class arch_prctl(simuvex.SimProcedure):

    IS_SYSCALL = True
    """
    Sets the architecture specific thread state based on the subfunction selected
    using the 'code' parameter.
    """
    def run(self, code, addr):
        
        if self.state.se.symbolic(code):
            raise simuvex.SimValueError("Code value passed to arch_prctl must be concrete.")

        code = self.state.se.any_int(code)
        
        #ARCH_SET_GS
        if code == 0x1001: 
            self.regs.gs = addr
        #ARCH_SET_FS
        elif code == 0x1002:
            self.regs.fs = addr
        #ARCH_GET_FS
        elif code == 0x1003:
            fs = self.regs.fs
            self.state.memory.store(addr,fs)
        #ARCH_GET_GS
        elif code == 0x1004:
            gs = self.regs.gs
            self.state.memory.store(addr,gs)
        else:
            #EINVAL is returned if code is not a valid subcommand.
            return 22
