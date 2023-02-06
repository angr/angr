import logging

from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)

######################################
# sprintf
######################################


class sprintf(FormatParser):
    # pylint:disable=arguments-differ

    def run(self, dst_ptr, fmt):  # pylint:disable=unused-argument
        # The format str is at index 1
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(
            dst_ptr + (out_str.size() // self.arch.byte_width), self.state.solver.BVV(0, self.arch.byte_width)
        )

        return out_str.size() // self.arch.byte_width
