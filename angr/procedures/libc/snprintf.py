import logging

from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)

######################################
# snprintf
######################################

class snprintf(FormatParser):

    def run(self, dst_ptr, size, fmt):  # pylint:disable=arguments-differ,unused-argument

        if self.state.solver.eval(size) == 0:
            return size

        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(dst_ptr + (out_str.size() // self.arch.byte_width), self.state.solver.BVV(0, 8))

        return out_str.size()//self.arch.byte_width

######################################
# __snprintf_chk
######################################

class __snprintf_chk(FormatParser):

    def run(self, dst_ptr, maxlen, flag, size, fmt):  # pylint:disable=arguments-differ,unused-argument

        # The format str is at index 4
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(dst_ptr + (out_str.size() // self.arch.byte_width), self.state.solver.BVV(0, 8))

        return out_str.size()//self.arch.byte_width
