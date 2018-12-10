import logging
import angr
from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)

class printf(FormatParser):
    def run(self):
        try:
            stdout = self.state.posix.get_fd(1)
            if stdout is None:
                return -1

            # The format str is at index 0
            fmt_str = self._parse(0)
            out_str = fmt_str.replace(1, self.arg)

            stdout.write_data(out_str, out_str.size() // 8)
            return out_str.size() // 8
        except angr.SimUnsatError:
            return self.state.solver.Unconstrained('printf', 32, uninitialized=False)

class __printf_chk(FormatParser):
    def run(self):
        try:
            stdout = self.state.posix.get_fd(1)
            if stdout is None:
                return -1

            # The format str is at index 1
            fmt_str = self._parse(1)
            out_str = fmt_str.replace(2, self.arg)

            stdout.write_data(out_str, out_str.size() // 8)
            return out_str.size() // 8
        except angr.SimUnsatError:
            return self.state.solver.Unconstrained('__printf_chk', 32, uninitialized=False)
