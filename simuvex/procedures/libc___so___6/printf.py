import logging
from simuvex.s_format import FormatParser

l = logging.getLogger("simuvex.procedures.libc_so_6.printf")

######################################
# _printf
######################################

class printf(FormatParser):

    def run(self):
        # The format str is at index 0
        out_str = self._parse(0)
        self.state.posix.write(1, out_str, out_str.size())

        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now
        self.ret()
        # l.debug("Got return address for %s: 0x%08x.", __file__, self._exits[0].concretize())
