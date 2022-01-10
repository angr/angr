import logging

from angr.procedures.stubs.format_parser import ScanfFormatParser

l = logging.getLogger(name=__name__)

class sscanf(ScanfFormatParser):
    #pylint:disable=arguments-differ,unused-argument
    def run(self, data, fmt):
        fmt_str = self._parse(fmt)
        items = fmt_str.interpret(self.va_arg, addr=data)
        return items
