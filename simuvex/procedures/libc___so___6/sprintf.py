import logging
from simuvex.s_format import FormatParser

l = logging.getLogger("simuvex.procedures.sprintf")

######################################
# sprintf
######################################

class sprintf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, dst_ptr):
        # The format str is at index 1
        out_str = self._parse(1)
        self.state.memory.store(dst_ptr, out_str)

        # size_t has size arch.bits
        return self.state.BV(out_str.size(), self.state.arch.bits)
