import logging

from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger("angr.procedures.libc.printf")

class printf(FormatParser):

    def run(self):
        # The format str is at index 0
        fmt_str = self._parse(0)
        out_str = fmt_str.replace(1, self.arg)

        self.state.posix.write(1, out_str, out_str.size() / 8)

        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now
        return out_str.size() / 8
        # l.debug("Got return address for %s: 0x%08x.", __file__, self._exits[0].concretize())

class __printf_chk(FormatParser):

    def run(self):
        # The format str is at index 1
        fmt_str = self._parse(1)
        out_str = fmt_str.replace(2, self.arg)

        self.state.posix.write(1, out_str, out_str.size() / 8)

        return out_str.size() / 8
