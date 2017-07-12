import logging

from angr.procedures.stubs.format_parser import FormatParser
from angr.sim_type import SimTypeInt, SimTypeString

l = logging.getLogger("angr.procedures.libc.scanf")

class scanf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, fmt):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        fmt_str = self._parse(0)

        # we're reading from stdin so the region is the file's content
        f = self.state.posix.get_file(0)
        region = f.content
        start = f.pos

        (end, items) = fmt_str.interpret(start, 1, self.arg, region=region)

        # do the read, correcting the internal file position and logging the action
        self.state.posix.read_from(0, end - start)

        return items
