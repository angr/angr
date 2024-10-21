from __future__ import annotations
import logging

from angr.procedures.stubs.format_parser import FormatParser

l = logging.getLogger(name=__name__)


class syslog(FormatParser):
    def run(self, priority, fmt):  # pylint:disable=arguments-differ
        fmt = self._parse(fmt)
        formatted = fmt.replace(self.va_arg)
        if not formatted.symbolic:
            formatted = self.state.solver.eval(formatted, cast_to=bytes)
        l.info("Syslog priority %s: %s", priority, formatted)
