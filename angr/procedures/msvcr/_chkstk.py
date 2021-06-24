import angr

import logging
l = logging.getLogger(name=__name__)

######################################
# _chkstk (MSDN: https://docs.microsoft.com/en-us/windows/win32/devnotes/-win32-chkstk)
# this implementation grows stack without simulating stack page probing
######################################

class _chkstk(angr.SimProcedure):
    def run(self):
        if self.state.arch.bits == 64:
            # Use registers for x86-64
            alloc = self.state.regs.rax
            if not alloc.concrete:
                raise ValueError("_chkstk requires a concrete parameter in rax")
        elif self.state.arch.bits == 32:
            # Use registers for x86
            alloc = self.state.regs.eax
            if not alloc.concrete:
                raise ValueError("_chkstk requires a concrete parameter in eax")
        else:
            raise NotImplementedError("_chkstk only implemented for x86 and x86-64")

        ret_address = self.state.stack_read(0, self.state.arch.bytes)
        l.debug("_chkstk called with parameter %s and return address %s", alloc, ret_address)

        # Assuming alloc already aligned by compiler
        self.state.regs.sp -= alloc
        self.state.stack_push(ret_address)
