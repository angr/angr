
import logging

from angr.procedures.stubs.format_parser import FormatParser
from angr.sim_type import SimTypeInt, SimTypeString

l = logging.getLogger(name=__name__)

class sscanf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, data, fmt):
        #pylint:disable=attribute-defined-outside-init
        fmt_str = self._parse(1)

        items = fmt_str.interpret(2, self.arg, addr=data)
        return items
