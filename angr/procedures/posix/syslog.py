import logging

from ..stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)
l.setLevel('INFO')

class syslog(FormatParser):
    def run(self, priority, fmt):
        fmt = self._parse(fmt)
        formatted = fmt.replace(self.va_arg)
        if not formatted.symbolic:
            formatted = self.state.solver.eval(formatted, cast_to=bytes)
        l.info("Syslog priority %s: %s", priority, formatted)
