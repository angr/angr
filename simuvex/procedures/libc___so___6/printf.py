import simuvex
import logging
import re

l = logging.getLogger(name="procedures.libc_so_6.printf")

######################################
# _printf
######################################

class printf(simuvex.SimProcedure):

    def run(self, fmtstr_ptr):

        fmt = self.state.se.any_str(self.state.mem_expr(fmtstr_ptr, 64))
        formats = self._parse_format_str(fmt)

        # We start at 1 as the first argument is the format string iteself
        argno = 1
        for f in formats:
            ptr = self.arg(argno)
            if f == "%c":
                xpr = self.state.mem_expr(ptr,1)
                import pdb; pdb.set_trace()
                #char = self.state.se.any_str(xpr)

            elif f == "%s":
                xpr = self.state.mem[ptr:].string

            elif f == "%d":
                xpr = self.state.mem_expr(ptr, 4)

            elif f == "%l":
                xpr = self.state.mem_expr(ptr, 8)

            else:
                raise Exception("Unknown format %s" % f)

            argno = argno + 1


        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now
        self.ret()
        # l.debug("Got return address for %s: 0x%08x.", __file__, self._exits[0].concretize())


    def _parse_format_str(self, fmt):
        args = re.findall(r'%[0-9]*[a-z]+', fmt)
        return args
