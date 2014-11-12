import simuvex
import logging

l = logging.getLogger(name="procedures.libc_so_6.printf")

######################################
# _printf
######################################

class printf(simuvex.SimProcedure):
    def run(self):
        # TODO: vararg types? oof
        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now
        self.ret()
        # l.debug("Got return address for %s: 0x%08x.", __file__, self._exits[0].concretize())
