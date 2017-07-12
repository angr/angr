
import logging

from angr.procedures.stubs.format_parser import FormatParser
from angr.sim_type import SimTypeInt, SimTypeString

l = logging.getLogger("angr.procedures.libc.sscanf")

class sscanf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, scan, fmt):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        fmt_str = self._parse(1)

        _, items = fmt_str.interpret(self.arg(0), 2, self.arg, region=self.state.memory)

        return items
