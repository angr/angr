import logging

from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)


class printf(FormatParser):
    def run(self, fmt):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        # The format str is at index 0
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)

        stdout.write_data(out_str, out_str.size() // 8)
        return out_str.size() // 8


class __printf_chk(FormatParser):
    def run(self, _, fmt):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        # The format str is at index 1
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)

        stdout.write_data(out_str, out_str.size() // 8)
        return out_str.size() // 8
