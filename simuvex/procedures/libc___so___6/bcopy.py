import simuvex

import itertools
import logging
l = logging.getLogger("simuvex.procedures.libc.bcopy")

bcopy_counter = itertools.count()

class bcopy(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        dst_addr = self.arg(0)
        src_addr = self.arg(1)
        limit = self.arg(2)

        self.ret(self.inline_call(simuvex.SimProcedures['libc.so.6']['memcpy'], dst_addr, src_addr, limit))
