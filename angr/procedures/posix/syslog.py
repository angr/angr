import logging

from ..stubs.format_parser import FormatParser

l = logging.getLogger('angr.procedures.posix.syslog')
l.setLevel('INFO')

class syslog(FormatParser):
    def run(self, priority):
        fmt = self._parse(1)
        formatted = fmt.replace(2, self.arg)
        l.info("Syslog priority %s: %s", priority, formatted)