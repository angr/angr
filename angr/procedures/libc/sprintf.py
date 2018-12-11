import logging

from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)

######################################
# sprintf
######################################

class sprintf(FormatParser):

    #pylint:disable=arguments-differ

    def run(self, dst_ptr):
        # The format str is at index 1
        fmt_str = self._parse(1)
        out_str = fmt_str.replace(2, self.arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(dst_ptr + (out_str.size() // 8), self.state.solver.BVV(0, 8))

        # size_t has size arch.bits
        return self.state.solver.BVV(out_str.size()//8, self.state.arch.bits)
