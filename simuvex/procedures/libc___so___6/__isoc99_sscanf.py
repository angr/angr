import simuvex
from simuvex.s_format import FormatParser
from simuvex.s_type import SimTypeInt, SimTypeString

import logging
l = logging.getLogger("simuvex.procedures.libc.system")

class __isoc99_sscanf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, scan, fmt):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        fmt_str = self._parse(1)

        _, items = fmt_str.interpret(self.arg(0), 2, self.arg, region=self.state.memory)

        return items
