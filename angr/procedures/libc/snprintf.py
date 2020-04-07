import logging

from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)

######################################
# snprintf
######################################

class snprintf(FormatParser):

    def run(self, dst_ptr, size):  # pylint:disable=arguments-differ,unused-argument

        if self.state.solver.eval(size) == 0:
            return size
        
        # The format str is at index 2
        fmt_str = self._parse(2)
        out_str = fmt_str.replace(3, self.arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(dst_ptr + (out_str.size() // 8), self.state.solver.BVV(0, 8))

        # size_t has size arch.bits
        return self.state.solver.BVV(out_str.size()//8, self.state.arch.bits)

######################################
# __snprintf_chk
######################################

class __snprintf_chk(FormatParser):

    def run(self, dst_ptr, maxlen, size):  # pylint:disable=arguments-differ,unused-argument

        # The format str is at index 4
        fmt_str = self._parse(4)
        out_str = fmt_str.replace(5, self.arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(dst_ptr + (out_str.size() // 8), self.state.solver.BVV(0, 8))

        # size_t has size arch.bits
        return self.state.solver.BVV(out_str.size()//8, self.state.arch.bits)
